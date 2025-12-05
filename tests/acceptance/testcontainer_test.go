package acceptance

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
)

// Test flags.
var (
	// parallelContainers controls how many containers to use for parallel test execution.
	// Default is 1 (sequential execution). Set higher for parallel tests.
	// Example: go test ./tests/acceptance -parallel-containers=5 .
	parallelContainers = flag.Int("parallel-containers", 1, "Number of SSH containers for parallel test execution (1 = sequential)")
)

// Global container pool - initialized lazily.
var pool *ContainerPool

// GetPool returns the global container pool, creating it if necessary.
func GetPool() *ContainerPool {
	if pool == nil {
		pool = NewContainerPool(*parallelContainers)
	}
	return pool
}

// ClosePool closes the global container pool.
func ClosePool() {
	if pool != nil {
		pool.Close()
		pool = nil
	}
}

// SSHTestContainer provides an SSH-enabled container for integration testing.
type SSHTestContainer struct {
	Container      testcontainers.Container
	Host           string
	Port           int
	User           string
	PrivateKey     string
	PrivateKeyPath string
}

// generateSSHKeyPair generates an RSA key pair for SSH testing.
func generateSSHKeyPair(t *testing.T) (privateKeyPEM, publicKeySSH string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create SSH public key: %v", err)
	}
	publicKeySSH = string(ssh.MarshalAuthorizedKey(publicKey))

	return privateKeyPEM, publicKeySSH
}

// SetupSSHContainer returns an SSH container for testing.
// Uses a container pool for efficient parallel test execution.
//
// Usage modes (controlled by -parallel-containers flag):.
//   - parallel-containers=1 (default): Sequential execution, one container reused
//   - parallel-containers=N: Up to N tests run in parallel, each with its own container
//
// Containers are automatically cleaned up between test uses.
func SetupSSHContainer(t *testing.T) *SSHTestContainer {
	t.Helper()

	if testing.Short() {
		t.Skip("Skipping container-based test in short mode")
	}

	// Use the global pool.
	return GetPool().Acquire(t)
}

// SetupIsolatedContainer creates a new container just for this test (not from pool).
// Use this when a test needs complete isolation or modifies container state.
func SetupIsolatedContainer(t *testing.T) *SSHTestContainer {
	t.Helper()

	if testing.Short() {
		t.Skip("Skipping container-based test in short mode")
	}

	return createNewContainer(t)
}

// createNewContainer creates a new container for a single test (not pooled).
func createNewContainer(t *testing.T) *SSHTestContainer {
	t.Helper()

	ctx := context.Background()
	privateKey, publicKey := generateSSHKeyPair(t)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key")
	if err := os.WriteFile(keyPath, []byte(privateKey), 0600); err != nil {
		t.Fatalf("failed to write private key: %v", err)
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
		t.Fatalf("failed to start container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get container host: %v", err)
	}

	mappedPort, err := container.MappedPort(ctx, "2222/tcp")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get mapped port: %v", err)
	}

	sshContainer := &SSHTestContainer{
		Container:      container,
		Host:           host,
		Port:           mappedPort.Int(),
		User:           "testuser",
		PrivateKey:     privateKey,
		PrivateKeyPath: keyPath,
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	})

	if err := waitForSSH(sshContainer, 30*time.Second); err != nil {
		t.Fatalf("SSH not ready: %v", err)
	}

	return sshContainer
}

// waitForSSH waits for SSH connection to be ready.
func waitForSSH(c *SSHTestContainer, timeout time.Duration) error {
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

// Address returns the SSH address in host:port format.
func (c *SSHTestContainer) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// RunCommand executes a command in the container via SSH.
func (c *SSHTestContainer) RunCommand(t *testing.T, command string) (string, error) {
	t.Helper()
	return c.runCommand(command)
}

// runCommand is the internal implementation for running commands.
func (c *SSHTestContainer) runCommand(command string) (string, error) {
	signer, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: c.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", c.Address(), config)
	if err != nil {
		return "", fmt.Errorf("failed to dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	return string(output), err
}

// ReadRemoteFile reads a file from the container.
func (c *SSHTestContainer) ReadRemoteFile(t *testing.T, path string) (string, error) {
	t.Helper()
	return c.runCommand(fmt.Sprintf("cat %s", path))
}

// FileExists checks if a file exists in the container.
func (c *SSHTestContainer) FileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := c.runCommand(fmt.Sprintf("test -f %s", path))
	return err == nil
}

// GetFileMode gets the file mode of a remote file.
func (c *SSHTestContainer) GetFileMode(t *testing.T, path string) (string, error) {
	t.Helper()
	return c.runCommand(fmt.Sprintf("stat -c '%%a' %s", path))
}

// FileExistsNoHelper checks if a file exists without requiring *testing.T (for use in check functions).
func (c *SSHTestContainer) FileExistsNoHelper(path string) bool {
	_, err := c.runCommand(fmt.Sprintf("test -f %s", path))
	return err == nil
}

// ReadRemoteFileNoHelper reads a file without requiring *testing.T (for use in check functions).
func (c *SSHTestContainer) ReadRemoteFileNoHelper(path string) (string, error) {
	return c.runCommand(fmt.Sprintf("cat %s", path))
}

// GetFileModeNoHelper gets file mode without requiring *testing.T (for use in check functions).
func (c *SSHTestContainer) GetFileModeNoHelper(path string) (string, error) {
	return c.runCommand(fmt.Sprintf("stat -c '%%a' %s", path))
}
