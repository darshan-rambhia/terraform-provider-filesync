package acceptance

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
)

// ContainerPool manages a pool of SSH containers for parallel test execution.
// Tests acquire containers from the pool and release them when done.
type ContainerPool struct {
	size          int
	containers    chan *SSHTestContainer
	allContainers []*SSHTestContainer
	initOnce      sync.Once
	initErr       error
	mu            sync.Mutex
	closed        bool
}

// NewContainerPool creates a new container pool with the specified size.
// Containers are created lazily on first Acquire call.
func NewContainerPool(size int) *ContainerPool {
	if size < 1 {
		size = 1
	}
	return &ContainerPool{
		size:       size,
		containers: make(chan *SSHTestContainer, size),
	}
}

// initialize creates all containers in the pool.
func (p *ContainerPool) initialize(t *testing.T) error {
	p.initOnce.Do(func() {
		t.Logf("Initializing container pool with %d containers...", p.size)

		p.allContainers = make([]*SSHTestContainer, 0, p.size)

		// Create containers in parallel for faster initialization.
		var wg sync.WaitGroup
		var mu sync.Mutex
		errors := make([]error, p.size)
		containers := make([]*SSHTestContainer, p.size)

		for i := 0; i < p.size; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				container, err := createPoolContainer(t, idx)
				if err != nil {
					errors[idx] = err
					return
				}
				containers[idx] = container
			}(i)
		}

		wg.Wait()

		// Check for errors and add successful containers to pool.
		for i, err := range errors {
			if err != nil {
				p.initErr = fmt.Errorf("failed to create container %d: %w", i, err)
				// Cleanup any containers that were created.
				for _, c := range containers {
					if c != nil && c.Container != nil {
						_ = c.Container.Terminate(context.Background())
					}
				}
				return
			}
		}

		// Add all containers to the pool.
		mu.Lock()
		for _, c := range containers {
			p.allContainers = append(p.allContainers, c)
			p.containers <- c
		}
		mu.Unlock()

		t.Logf("Container pool initialized with %d containers", p.size)
	})

	return p.initErr
}

// Acquire gets a container from the pool, blocking if none are available.
// The container is automatically released when the test completes.
// Remote files are cleaned up before returning the container.
func (p *ContainerPool) Acquire(t *testing.T) *SSHTestContainer {
	t.Helper()

	if testing.Short() {
		t.Skip("Skipping container-based test in short mode")
	}

	// Initialize pool on first acquire.
	if err := p.initialize(t); err != nil {
		t.Fatalf("failed to initialize container pool: %v", err)
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		t.Fatal("container pool is closed")
	}
	p.mu.Unlock()

	// Get a container from the pool (blocks if none available).
	t.Log("Acquiring container from pool...")
	container := <-p.containers
	t.Logf("Acquired container at %s:%d", container.Host, container.Port)

	// Clean up any leftover files from previous tests.
	cleanupContainer(container)

	// Register cleanup to return container to pool.
	t.Cleanup(func() {
		// Clean up test files before returning to pool.
		cleanupContainer(container)

		p.mu.Lock()
		defer p.mu.Unlock()

		if !p.closed {
			p.containers <- container
			t.Log("Released container back to pool")
		}
	})

	return container
}

// Close terminates all containers in the pool.
func (p *ContainerPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true

	// Close the channel to prevent new acquires.
	close(p.containers)

	// Terminate all containers.
	ctx := context.Background()
	for _, c := range p.allContainers {
		if c != nil && c.Container != nil {
			_ = c.Container.Terminate(ctx)
		}
	}
}

// Size returns the pool size.
func (p *ContainerPool) Size() int {
	return p.size
}

// cleanupContainer removes test files from a container.
func cleanupContainer(c *SSHTestContainer) {
	// Remove common test directories.
	commands := []string{
		"rm -rf /tmp/test-* 2>/dev/null || true",
		"rm -rf /tmp/deeply 2>/dev/null || true",
	}

	for _, cmd := range commands {
		_, _ = c.runCommand(cmd)
	}
}

// createPoolContainer creates a single container for the pool.
func createPoolContainer(t *testing.T, index int) (*SSHTestContainer, error) {
	ctx := context.Background()

	// Generate SSH key pair.
	privateKey, publicKey, err := generateSSHKeyPairForPool()
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH key: %w", err)
	}

	// Create temp directory for this container's key.
	tmpDir := t.TempDir()

	keyPath := filepath.Join(tmpDir, "test_key")
	if err := os.WriteFile(keyPath, []byte(privateKey), 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:        "linuxserver/openssh-server:latest",
		ExposedPorts: []string{"2222/tcp"},
		Env: map[string]string{
			"PUID":            "1000",
			"PGID":            "1000",
			"TZ":              "UTC",
			"USER_NAME":       "testuser",
			"PUBLIC_KEY":      publicKey,
			"SUDO_ACCESS":     "true",
			"PASSWORD_ACCESS": "false",
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("2222/tcp"),
			wait.ForLog("sshd is listening on port").WithStartupTimeout(60*time.Second),
		),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	mappedPort, err := container.MappedPort(ctx, "2222/tcp")
	if err != nil {
		_ = container.Terminate(ctx)
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("failed to get mapped port: %w", err)
	}

	sshContainer := &SSHTestContainer{
		Container:      container,
		Host:           host,
		Port:           mappedPort.Int(),
		User:           "testuser",
		PrivateKey:     privateKey,
		PrivateKeyPath: keyPath,
	}

	// Wait for SSH to be ready.
	if err := waitForSSHReady(sshContainer, 30*time.Second); err != nil {
		_ = container.Terminate(ctx)
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("SSH not ready: %w", err)
	}

	t.Logf("Created pool container %d at %s:%d", index, host, mappedPort.Int())
	return sshContainer, nil
}

// generateSSHKeyPairForPool generates an SSH key pair (non-test version for pool init).
func generateSSHKeyPairForPool() (privateKeyPEM, publicKeySSH string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create SSH public key: %w", err)
	}
	publicKeySSH = string(ssh.MarshalAuthorizedKey(publicKey))

	return privateKeyPEM, publicKeySSH, nil
}

// waitForSSHReady waits for SSH to be ready (non-test version).
func waitForSSHReady(c *SSHTestContainer, timeout time.Duration) error {
	signer, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: c.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)

	for time.Now().Before(deadline) {
		client, err := ssh.Dial("tcp", addr, config)
		if err == nil {
			client.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for SSH at %s", addr)
}
