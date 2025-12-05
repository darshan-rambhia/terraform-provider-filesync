package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// AuthMethod represents the SSH authentication method to use.
type AuthMethod string

const (
	// AuthMethodPrivateKey uses SSH private key authentication (default).
	AuthMethodPrivateKey AuthMethod = "private_key"
	// AuthMethodPassword uses password authentication.
	AuthMethodPassword AuthMethod = "password"
	// AuthMethodCertificate uses SSH certificate authentication.
	AuthMethodCertificate AuthMethod = "certificate"
)

// Config holds SSH connection configuration.
type Config struct {
	Host string
	Port int
	User string

	// Authentication method (defaults to private_key if not specified).
	AuthMethod AuthMethod

	// Private key authentication.
	PrivateKey string // Key content (PEM encoded)
	KeyPath    string // Path to key file

	// Password authentication.
	Password string

	// Certificate authentication.
	Certificate     string // Certificate content
	CertificatePath string // Path to certificate file
	// For certificate auth, you also need the private key that corresponds to the cert.

	// Connection options.
	Timeout time.Duration // Connection timeout (default 30s)

	// Host key verification.
	// If KnownHostsFile is set, uses that file for verification.
	// If InsecureIgnoreHostKey is true, skips verification (NOT RECOMMENDED).
	// Default behavior: uses ~/.ssh/known_hosts if it exists.
	KnownHostsFile        string // Path to known_hosts file
	InsecureIgnoreHostKey bool   // Skip host key verification (DANGEROUS)

	// Bastion/Jump host configuration for multihop SSH.
	BastionHost     string
	BastionPort     int
	BastionUser     string
	BastionKey      string // Private key content for bastion
	BastionKeyPath  string // Path to private key for bastion
	BastionPassword string // Password for bastion (if using password auth)

	// SSH Agent forwarding.
	AgentForwarding bool
}

// ClientInterface defines the interface for SSH/SFTP operations.
// This allows for mocking in tests.
type ClientInterface interface {
	// Close closes the SSH connection.
	Close() error
	// UploadFile uploads a local file to the remote host.
	UploadFile(localPath, remotePath string) error
	// GetFileHash returns the SHA256 hash of a remote file.
	GetFileHash(remotePath string) (string, error)
	// SetFileAttributes sets ownership and permissions on a remote file.
	SetFileAttributes(remotePath, owner, group, mode string) error
	// DeleteFile removes a file from the remote host.
	DeleteFile(remotePath string) error
	// FileExists checks if a file exists on the remote host.
	FileExists(remotePath string) (bool, error)
	// GetFileInfo returns information about a remote file.
	GetFileInfo(remotePath string) (os.FileInfo, error)
	// ReadFileContent reads the content of a remote file.
	ReadFileContent(remotePath string, maxBytes int64) ([]byte, error)
}

// Client wraps SSH and SFTP connections for file operations.
type Client struct {
	sshClient     *ssh.Client
	sftpClient    SFTPClientInterface
	bastionClient *ssh.Client // nil if no bastion host
}

// Ensure Client implements ClientInterface.
var _ ClientInterface = (*Client)(nil)

// NewClientWithSFTP creates a Client with a custom SFTP client implementation.
// This is primarily used for testing with mock SFTP clients.
func NewClientWithSFTP(sftpClient SFTPClientInterface, sshClient *ssh.Client) *Client {
	return &Client{
		sshClient:  sshClient,
		sftpClient: sftpClient,
	}
}

// SFTPClientInterface abstracts SFTP operations for testing.
// This allows mocking the SFTP client in unit tests.
type SFTPClientInterface interface {
	Open(path string) (SFTPFile, error)
	Create(path string) (SFTPFile, error)
	Remove(path string) error
	Stat(path string) (os.FileInfo, error)
	Chmod(path string, mode os.FileMode) error
	MkdirAll(path string) error
	Close() error
}

// SFTPFile abstracts file operations for testing.
type SFTPFile interface {
	io.Reader
	io.Writer
	io.Closer
}

// SFTPClientWrapper wraps the real sftp.Client to implement SFTPClientInterface.
type SFTPClientWrapper struct {
	client *sftp.Client
}

// Ensure SFTPClientWrapper implements SFTPClientInterface.
var _ SFTPClientInterface = (*SFTPClientWrapper)(nil)

func (w *SFTPClientWrapper) Open(path string) (SFTPFile, error) {
	return w.client.Open(path)
}

func (w *SFTPClientWrapper) Create(path string) (SFTPFile, error) {
	return w.client.Create(path)
}

func (w *SFTPClientWrapper) Remove(path string) error {
	return w.client.Remove(path)
}

func (w *SFTPClientWrapper) Stat(path string) (os.FileInfo, error) {
	return w.client.Stat(path)
}

func (w *SFTPClientWrapper) Chmod(path string, mode os.FileMode) error {
	return w.client.Chmod(path, mode)
}

func (w *SFTPClientWrapper) MkdirAll(path string) error {
	return w.client.MkdirAll(path)
}

func (w *SFTPClientWrapper) Close() error {
	return w.client.Close()
}

// NewClient creates a new SSH/SFTP client.
func NewClient(config Config) (*Client, error) {
	authMethods, err := buildAuthMethods(config)
	if err != nil {
		return nil, err
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication method configured")
	}

	// Set default timeout.
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Build host key callback.
	hostKeyCallback, err := buildHostKeyCallback(config)
	if err != nil {
		return nil, fmt.Errorf("failed to configure host key verification: %w", err)
	}

	// Create SSH config for target host.
	sshConfig := &ssh.ClientConfig{
		User:            config.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}

	var sshClient *ssh.Client
	var bastionClient *ssh.Client

	targetAddr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	// Check if we need to connect through a bastion host.
	if config.BastionHost != "" {
		bastionClient, err = connectToBastion(config, timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to bastion host: %w", err)
		}

		// Connect to target through bastion.
		conn, err := bastionClient.Dial("tcp", targetAddr)
		if err != nil {
			bastionClient.Close()
			return nil, fmt.Errorf("failed to dial target through bastion: %w", err)
		}

		ncc, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, sshConfig)
		if err != nil {
			conn.Close()
			bastionClient.Close()
			return nil, fmt.Errorf("failed to create SSH connection through bastion: %w", err)
		}

		sshClient = ssh.NewClient(ncc, chans, reqs)
	} else {
		// Direct connection.
		sshClient, err = ssh.Dial("tcp", targetAddr, sshConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
		}
	}

	// Create SFTP client.
	rawSftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		if bastionClient != nil {
			bastionClient.Close()
		}
		return nil, fmt.Errorf("failed to create SFTP client: %w", err)
	}

	return &Client{
		sshClient:     sshClient,
		sftpClient:    &SFTPClientWrapper{client: rawSftpClient},
		bastionClient: bastionClient,
	}, nil
}

// connectToBastion establishes a connection to the bastion/jump host.
func connectToBastion(config Config, timeout time.Duration) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	// Build auth methods for bastion.
	if config.BastionPassword != "" {
		authMethods = append(authMethods, ssh.Password(config.BastionPassword))
	} else {
		// Use key-based auth for bastion.
		var keyData []byte
		var err error

		if config.BastionKey != "" {
			keyData = []byte(config.BastionKey)
		} else if config.BastionKeyPath != "" {
			keyData, err = os.ReadFile(config.BastionKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read bastion key file: %w", err)
			}
		} else {
			// Fall back to target's key for bastion.
			if config.PrivateKey != "" {
				keyData = []byte(config.PrivateKey)
			} else if config.KeyPath != "" {
				keyData, err = os.ReadFile(config.KeyPath)
				if err != nil {
					return nil, fmt.Errorf("failed to read key file for bastion: %w", err)
				}
			} else {
				return nil, fmt.Errorf("no SSH key configured for bastion host")
			}
		}

		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bastion SSH key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	bastionUser := config.BastionUser
	if bastionUser == "" {
		bastionUser = config.User // Fall back to target user
	}

	bastionPort := config.BastionPort
	if bastionPort == 0 {
		bastionPort = 22
	}

	// Build host key callback for bastion.
	hostKeyCallback, err := buildHostKeyCallback(config)
	if err != nil {
		return nil, fmt.Errorf("failed to configure host key verification for bastion: %w", err)
	}

	bastionConfig := &ssh.ClientConfig{
		User:            bastionUser,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}

	bastionAddr := fmt.Sprintf("%s:%d", config.BastionHost, bastionPort)
	return ssh.Dial("tcp", bastionAddr, bastionConfig)
}

// buildHostKeyCallback creates an SSH host key callback based on configuration.
// Priority:
// 1. If InsecureIgnoreHostKey is true, skip verification (NOT RECOMMENDED).
// 2. If KnownHostsFile is set, use that file.
// 3. Default: use ~/.ssh/known_hosts if it exists, otherwise skip verification with warning.
func buildHostKeyCallback(config Config) (ssh.HostKeyCallback, error) {
	// Option 1: Explicitly skip verification (dangerous but explicit).
	if config.InsecureIgnoreHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	// Option 2: Use specified known_hosts file.
	if config.KnownHostsFile != "" {
		expandedPath := expandPath(config.KnownHostsFile)
		callback, err := knownhosts.New(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts file %s: %w", expandedPath, err)
		}
		return callback, nil
	}

	// Option 3: Try default known_hosts locations.
	homeDir, err := os.UserHomeDir()
	if err == nil {
		defaultKnownHosts := filepath.Join(homeDir, ".ssh", "known_hosts")
		if _, err := os.Stat(defaultKnownHosts); err == nil {
			callback, err := knownhosts.New(defaultKnownHosts)
			if err == nil {
				return callback, nil
			}
			// If we can't parse the file, fall through to permissive mode.
		}
	}

	// Fallback: Accept any host key but log a warning.
	// This maintains backward compatibility while being more explicit.
	// In production, users should configure known_hosts or set InsecureIgnoreHostKey explicitly.
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// Accept the key but this is insecure.
		// TODO: Consider logging a warning here.
		return nil
	}, nil
}

// expandPath expands ~ to home directory.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(homeDir, path[2:])
		}
	}
	return path
}

// validOwnerGroupPattern matches valid Unix user/group names.
// Standard Unix names: start with letter or underscore, followed by alphanumeric, underscore, or hyphen.
// Also allows numeric UIDs/GIDs.
var validOwnerGroupPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$|^[0-9]+$`)

// validateOwnerGroup checks if an owner or group name is valid and safe.
func validateOwnerGroup(name, fieldName string) error {
	if name == "" {
		return nil
	}
	if len(name) > 32 {
		return fmt.Errorf("%s name too long (max 32 characters): %s", fieldName, name)
	}
	if !validOwnerGroupPattern.MatchString(name) {
		return fmt.Errorf("invalid %s name (must be alphanumeric, underscore, hyphen, or numeric): %s", fieldName, name)
	}
	return nil
}

// shellQuote returns a shell-escaped version of the string.
// Uses single quotes and escapes any embedded single quotes.
func shellQuote(s string) string {
	// If empty, return empty quoted string.
	if s == "" {
		return "''"
	}
	// Replace single quotes with '\'' (end quote, escaped quote, start quote).
	escaped := strings.ReplaceAll(s, "'", "'\"'\"'")
	return "'" + escaped + "'"
}

// validModePattern matches valid Unix file permission modes.
// Accepts 3-4 octal digits (e.g., "644", "0755", "1777").
var validModePattern = regexp.MustCompile(`^[0-7]{3,4}$`)

// ValidateMode checks if a file mode string is valid.
// Returns an error if the mode is invalid.
func ValidateMode(mode string) error {
	if mode == "" {
		return nil
	}
	if !validModePattern.MatchString(mode) {
		return fmt.Errorf("invalid mode %q: must be 3-4 octal digits (e.g., \"644\", \"0755\")", mode)
	}
	return nil
}

// buildAuthMethods constructs SSH auth methods based on config.
func buildAuthMethods(config Config) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	// Determine auth method - if not explicitly set, infer from provided credentials.
	authMethod := config.AuthMethod
	if authMethod == "" {
		authMethod = inferAuthMethod(config)
	}

	switch authMethod {
	case AuthMethodPassword:
		if config.Password == "" {
			return nil, fmt.Errorf("password authentication requires password to be set")
		}
		authMethods = append(authMethods, ssh.Password(config.Password))

	case AuthMethodCertificate:
		certAuth, err := buildCertificateAuth(config)
		if err != nil {
			return nil, fmt.Errorf("certificate authentication failed: %w", err)
		}
		authMethods = append(authMethods, certAuth)

	case AuthMethodPrivateKey, "":
		// Default to private key auth.
		keyAuth, err := buildPrivateKeyAuth(config)
		if err != nil {
			return nil, err
		}
		authMethods = append(authMethods, keyAuth)
	}

	return authMethods, nil
}

// inferAuthMethod determines auth method from provided credentials.
func inferAuthMethod(config Config) AuthMethod {
	if config.Password != "" {
		return AuthMethodPassword
	}
	if config.Certificate != "" || config.CertificatePath != "" {
		return AuthMethodCertificate
	}
	return AuthMethodPrivateKey
}

// buildPrivateKeyAuth creates a public key auth method from private key.
func buildPrivateKeyAuth(config Config) (ssh.AuthMethod, error) {
	var keyData []byte
	var err error

	if config.PrivateKey != "" {
		keyData = []byte(config.PrivateKey)
	} else if config.KeyPath != "" {
		keyData, err = os.ReadFile(config.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read SSH key file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no SSH private key provided (set private_key or key_path)")
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	return ssh.PublicKeys(signer), nil
}

// buildCertificateAuth creates certificate-based authentication
// SSH certificates are signed by a CA and provide identity verification.
func buildCertificateAuth(config Config) (ssh.AuthMethod, error) {
	// First, load the private key.
	var keyData []byte
	var err error

	if config.PrivateKey != "" {
		keyData = []byte(config.PrivateKey)
	} else if config.KeyPath != "" {
		keyData, err = os.ReadFile(config.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("certificate auth requires private key (set private_key or key_path)")
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Load the certificate.
	var certData []byte
	if config.Certificate != "" {
		certData = []byte(config.Certificate)
	} else if config.CertificatePath != "" {
		certData, err = os.ReadFile(config.CertificatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("certificate auth requires certificate (set certificate or certificate_path)")
	}

	// Parse the certificate.
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("provided file is not an SSH certificate")
	}

	// Create a signer that uses the certificate.
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate signer: %w", err)
	}

	return ssh.PublicKeys(certSigner), nil
}

// Close closes SFTP, SSH, and bastion connections.
func (c *Client) Close() error {
	if c.sftpClient != nil {
		c.sftpClient.Close()
	}
	if c.sshClient != nil {
		c.sshClient.Close()
	}
	if c.bastionClient != nil {
		c.bastionClient.Close()
	}
	return nil
}

// UploadFile uploads a local file to the remote host.
func (c *Client) UploadFile(localPath, remotePath string) error {
	// Open local file.
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer localFile.Close()

	// Create remote file (creates parent directories if needed).
	// Use filepath.Dir for safe path parsing (handles edge cases like "/file.txt").
	remoteDir := filepath.Dir(remotePath)
	if remoteDir != "" && remoteDir != "/" && remoteDir != "." {
		if err := c.sftpClient.MkdirAll(remoteDir); err != nil {
			return fmt.Errorf("failed to create remote directory %s: %w", remoteDir, err)
		}
	}

	remoteFile, err := c.sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer remoteFile.Close()

	// Copy content.
	_, err = io.Copy(remoteFile, localFile)
	if err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	return nil
}

// GetFileHash returns the SHA256 hash of a remote file.
func (c *Client) GetFileHash(remotePath string) (string, error) {
	file, err := c.sftpClient.Open(remotePath)
	if err != nil {
		return "", fmt.Errorf("failed to open remote file: %w", err)
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("failed to read remote file: %w", err)
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// SetFileAttributes sets ownership and permissions on a remote file.
func (c *Client) SetFileAttributes(remotePath, owner, group, mode string) error {
	// Validate owner and group names to prevent command injection.
	if err := validateOwnerGroup(owner, "owner"); err != nil {
		return err
	}
	if err := validateOwnerGroup(group, "group"); err != nil {
		return err
	}

	// Validate mode format before attempting to parse.
	if err := ValidateMode(mode); err != nil {
		return err
	}

	// Set permissions via SFTP.
	if mode != "" {
		modeInt, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid mode %s: %w", mode, err)
		}
		if err := c.sftpClient.Chmod(remotePath, os.FileMode(modeInt)); err != nil {
			return fmt.Errorf("failed to set permissions: %w", err)
		}
	}

	// Set ownership via SSH command (chown not available in SFTP).
	if owner != "" || group != "" {
		var ownership string
		if owner != "" && group != "" {
			// Both owner and group specified: owner:group.
			ownership = owner + ":" + group
		} else if owner != "" {
			// Only owner specified: just owner.
			ownership = owner
		} else {
			// Only group specified: :group.
			ownership = ":" + group
		}

		session, err := c.sshClient.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create SSH session: %w", err)
		}
		defer session.Close()

		// Use shell quoting for remotePath to prevent command injection.
		// Owner/group are validated above to contain only safe characters.
		cmd := fmt.Sprintf("chown %s %s", ownership, shellQuote(remotePath))
		if err := session.Run(cmd); err != nil {
			return fmt.Errorf("failed to set ownership: %w", err)
		}
	}

	return nil
}

// DeleteFile removes a file from the remote host.
func (c *Client) DeleteFile(remotePath string) error {
	err := c.sftpClient.Remove(remotePath)
	if err != nil {
		// Check if file doesn't exist (already deleted).
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to delete remote file: %w", err)
	}
	return nil
}

// FileExists checks if a file exists on the remote host.
func (c *Client) FileExists(remotePath string) (bool, error) {
	_, err := c.sftpClient.Stat(remotePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetFileInfo returns information about a remote file.
func (c *Client) GetFileInfo(remotePath string) (os.FileInfo, error) {
	return c.sftpClient.Stat(remotePath)
}

// ReadFileContent reads the content of a remote file.
// If maxBytes is > 0, only reads up to that many bytes.
func (c *Client) ReadFileContent(remotePath string, maxBytes int64) ([]byte, error) {
	file, err := c.sftpClient.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open remote file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file
	if maxBytes > 0 {
		reader = io.LimitReader(file, maxBytes)
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote file: %w", err)
	}

	return content, nil
}

// IsBinaryContent checks if content appears to be binary (contains null bytes).
func IsBinaryContent(content []byte) bool {
	for _, b := range content {
		if b == 0 {
			return true
		}
	}
	return false
}
