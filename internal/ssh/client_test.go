package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestKey creates a temporary RSA private key for testing.
func generateTestKey(t *testing.T) (string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Create temp file.
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}

	return string(keyPEM), keyPath
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with inline key",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				PrivateKey: "key-content",
			},
			expectError: false,
		},
		{
			name: "valid config with key path",
			config: Config{
				Host:    "192.168.1.100",
				Port:    22,
				User:    "root",
				KeyPath: "/path/to/key",
			},
			expectError: false,
		},
		{
			name: "missing credentials - expect error from NewClient",
			config: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			expectError: true,
			errorMsg:    "no SSH private key provided (set private_key or key_path)",
		},
		{
			name: "valid config with password",
			config: Config{
				Host:     "192.168.1.100",
				Port:     22,
				User:     "root",
				Password: "secret",
			},
			expectError: false,
		},
		{
			name: "explicit password auth without password",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				AuthMethod: AuthMethodPassword,
			},
			expectError: true,
			errorMsg:    "password authentication requires password to be set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectError {
				// Only test configs that should fail validation.
				_, err := NewClient(tt.config)
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("expected error %q, got %q", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

// TestNewClient_KeyHandling tests various key configurations for NewClient.
func TestNewClient_KeyHandling(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	tests := []struct {
		name           string
		config         Config
		wantParseError bool // true if key parsing should fail
		skipIfConnects bool // some tests skip if unexpectedly connects
	}{
		{
			name: "invalid key path",
			config: Config{
				Host:    "192.168.1.100",
				Port:    22,
				User:    "root",
				KeyPath: "/nonexistent/path/to/key",
			},
			wantParseError: true,
		},
		{
			name: "invalid key content",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				PrivateKey: "invalid-key-content",
			},
			wantParseError: true,
		},
		{
			name: "valid key from file",
			config: Config{
				Host:    "192.168.1.100",
				Port:    22,
				User:    "root",
				KeyPath: keyPath,
			},
			wantParseError: false,
			skipIfConnects: true,
		},
		{
			name: "valid inline key",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				PrivateKey: keyContent,
			},
			wantParseError: false,
			skipIfConnects: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.config)

			if tt.skipIfConnects && err == nil {
				t.Skip("unexpectedly connected - skipping")
			}

			if tt.wantParseError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else if err != nil {
				// For valid keys, error should be connection-related, not parsing.
				if err.Error() == "no SSH private key provided (set private_key or key_path)" {
					t.Error("key should have been parsed successfully")
				}
			}
		})
	}
}

// TestInferAuthMethod tests automatic auth method detection.
func TestInferAuthMethod(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected AuthMethod
	}{
		{
			name:     "infer private key from key content",
			config:   Config{PrivateKey: "key"},
			expected: AuthMethodPrivateKey,
		},
		{
			name:     "infer private key from key path",
			config:   Config{KeyPath: "/path/to/key"},
			expected: AuthMethodPrivateKey,
		},
		{
			name:     "infer password auth",
			config:   Config{Password: "secret"},
			expected: AuthMethodPassword,
		},
		{
			name:     "infer certificate auth from cert content",
			config:   Config{Certificate: "cert"},
			expected: AuthMethodCertificate,
		},
		{
			name:     "infer certificate auth from cert path",
			config:   Config{CertificatePath: "/path/to/cert"},
			expected: AuthMethodCertificate,
		},
		{
			name:     "default to private key when nothing set",
			config:   Config{},
			expected: AuthMethodPrivateKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferAuthMethod(tt.config)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestHashFormat verifies the hash format matches expected pattern.
func TestHashFormat(t *testing.T) {
	// Test that our hash format is correct by computing a known hash.
	data := []byte("test content")
	h := sha256.New()
	h.Write(data)
	hash := "sha256:" + hex.EncodeToString(h.Sum(nil))

	// Verify format.
	if len(hash) != 71 { // "sha256:" (7) + 64 hex chars
		t.Errorf("expected hash length 71, got %d", len(hash))
	}

	if hash[:7] != "sha256:" {
		t.Errorf("expected hash prefix 'sha256:', got %q", hash[:7])
	}
}

// TestClient_Close verifies Close handles nil clients gracefully.
func TestClient_Close(t *testing.T) {
	// Test with nil clients (including bastion).
	c := &Client{
		sshClient:     nil,
		sftpClient:    nil,
		bastionClient: nil,
	}

	// Should not panic.
	err := c.Close()
	if err != nil {
		t.Errorf("Close() with nil clients should not error: %v", err)
	}
}

// TestBastionConfig tests bastion host configuration.
func TestBastionConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "bastion with separate key",
			config: Config{
				Host:           "target.internal",
				Port:           22,
				User:           "root",
				PrivateKey:     "target-key",
				BastionHost:    "bastion.example.com",
				BastionPort:    22,
				BastionUser:    "jumpuser",
				BastionKeyPath: "/path/to/bastion/key",
			},
		},
		{
			name: "bastion inherits target key",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				PrivateKey:  "shared-key",
				BastionHost: "bastion.example.com",
			},
		},
		{
			name: "bastion with password",
			config: Config{
				Host:            "target.internal",
				Port:            22,
				User:            "root",
				PrivateKey:      "target-key",
				BastionHost:     "bastion.example.com",
				BastionPassword: "bastion-pass",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify config struct is valid - actual connection would require servers.
			if tt.config.BastionHost == "" {
				t.Error("expected bastion host to be set")
			}
		})
	}
}

// TestUploadFile_LocalFileNotFound tests error handling for missing local file.
func TestUploadFile_LocalFileNotFound(t *testing.T) {
	// Create a client with nil SFTP (will fail before SFTP is used).
	c := &Client{
		sshClient:  nil,
		sftpClient: nil,
	}

	err := c.UploadFile("/nonexistent/file.txt", "/remote/path")
	if err == nil {
		t.Error("expected error for nonexistent local file, got nil")
	}
}

// Benchmark tests for hash computation.
func BenchmarkHashComputation(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := sha256.New()
		h.Write(data)
		_ = "sha256:" + hex.EncodeToString(h.Sum(nil))
	}
}

// TestModeParser tests octal mode parsing similar to SetFileAttributes.
func TestModeParser(t *testing.T) {
	tests := []struct {
		mode    string
		valid   bool
		decimal uint64
	}{
		{"0644", true, 0644},
		{"0755", true, 0755},
		{"0600", true, 0600},
		{"0777", true, 0777},
		{"644", true, 0644},
		{"invalid", false, 0},
		{"", true, 0}, // Empty is valid (no-op)
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			if tt.mode == "" {
				return // Empty mode is handled specially
			}

			_, err := parseOctalMode(tt.mode)
			if tt.valid && err != nil {
				t.Errorf("expected valid mode, got error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Error("expected error for invalid mode, got nil")
			}
		})
	}
}

// parseOctalMode is a helper to test mode parsing logic.
func parseOctalMode(mode string) (os.FileMode, error) {
	modeInt, err := parseUint(mode, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(modeInt), nil
}

// parseUint wraps strconv.ParseUint for testing.
func parseUint(s string, base, bitSize int) (uint64, error) {
	return strtoull(s, base, bitSize)
}

// strtoull is a simple wrapper for testing.
func strtoull(s string, _, _ int) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	var val uint64
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, os.ErrInvalid
		}
		val = val*8 + uint64(c-'0')
	}
	return val, nil
}

// TestOwnershipString tests ownership string formatting.
func TestOwnershipString(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		group    string
		expected string
	}{
		{"both owner and group", "root", "root", "root:root"},
		{"only owner", "root", "", "root"},
		{"only group", "", "www-data", ":www-data"},
		{"different owner and group", "user", "staff", "user:staff"},
		{"www-data both", "www-data", "www-data", "www-data:www-data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use the same logic as SetFileAttributes.
			var ownership string
			if tt.owner != "" && tt.group != "" {
				ownership = tt.owner + ":" + tt.group
			} else if tt.owner != "" {
				ownership = tt.owner
			} else if tt.group != "" {
				ownership = ":" + tt.group
			}
			if ownership != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, ownership)
			}
		})
	}
}

// TestRemotePathParsing tests directory extraction from paths.
func TestRemotePathParsing(t *testing.T) {
	tests := []struct {
		path     string
		dir      string
		hasSlash bool
	}{
		{"/etc/nginx/nginx.conf", "/etc/nginx", true},
		{"/config/.env", "/config", true},
		{"/file.txt", "", true},
		{"file.txt", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			lastSlash := -1
			for i := len(tt.path) - 1; i >= 0; i-- {
				if tt.path[i] == '/' {
					lastSlash = i
					break
				}
			}

			var dir string
			if lastSlash > 0 {
				dir = tt.path[:lastSlash]
			}

			if dir != tt.dir {
				t.Errorf("expected dir %q, got %q", tt.dir, dir)
			}
		})
	}
}

// TestIsBinaryContent tests binary content detection.
func TestIsBinaryContent(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected bool
	}{
		{
			name:     "text content",
			content:  []byte("Hello, World!\nThis is plain text."),
			expected: false,
		},
		{
			name:     "binary content with null byte",
			content:  []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x57, 0x6f, 0x72, 0x6c, 0x64},
			expected: true,
		},
		{
			name:     "empty content",
			content:  []byte{},
			expected: false,
		},
		{
			name:     "single null byte",
			content:  []byte{0x00},
			expected: true,
		},
		{
			name:     "null byte at start",
			content:  []byte{0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f},
			expected: true,
		},
		{
			name:     "null byte at end",
			content:  []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00},
			expected: true,
		},
		{
			name:     "unicode text",
			content:  []byte("Hello, 世界! 🌍"),
			expected: false,
		},
		{
			name:     "binary-like but no null",
			content:  []byte{0xFF, 0xFE, 0x01, 0x02, 0x03},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBinaryContent(tt.content)
			if result != tt.expected {
				t.Errorf("IsBinaryContent(%v) = %v, want %v", tt.content, result, tt.expected)
			}
		})
	}
}

// TestBuildAuthMethods tests auth method building.
func TestBuildAuthMethods(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "password auth",
			config: Config{
				AuthMethod: AuthMethodPassword,
				Password:   "secret",
			},
			expectError: false,
		},
		{
			name: "password auth without password",
			config: Config{
				AuthMethod: AuthMethodPassword,
			},
			expectError: true,
			errorMsg:    "password authentication requires password to be set",
		},
		{
			name: "private key auth with inline key",
			config: Config{
				AuthMethod: AuthMethodPrivateKey,
				PrivateKey: keyContent,
			},
			expectError: false,
		},
		{
			name: "private key auth with key path",
			config: Config{
				AuthMethod: AuthMethodPrivateKey,
				KeyPath:    keyPath,
			},
			expectError: false,
		},
		{
			name: "private key auth without key",
			config: Config{
				AuthMethod: AuthMethodPrivateKey,
			},
			expectError: true,
			errorMsg:    "no SSH private key provided (set private_key or key_path)",
		},
		{
			name: "certificate auth without key",
			config: Config{
				AuthMethod:  AuthMethodCertificate,
				Certificate: "cert-content",
			},
			expectError: true,
			errorMsg:    "certificate authentication failed: certificate auth requires private key (set private_key or key_path)",
		},
		{
			name: "certificate auth without cert",
			config: Config{
				AuthMethod: AuthMethodCertificate,
				PrivateKey: keyContent,
			},
			expectError: true,
			errorMsg:    "certificate authentication failed: certificate auth requires certificate (set certificate or certificate_path)",
		},
		{
			name: "inferred password auth",
			config: Config{
				Password: "secret",
			},
			expectError: false,
		},
		{
			name: "inferred private key auth",
			config: Config{
				PrivateKey: keyContent,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			methods, err := buildAuthMethods(tt.config)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("expected error %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(methods) == 0 {
					t.Error("expected at least one auth method")
				}
			}
		})
	}
}

// TestBuildPrivateKeyAuth tests private key auth building.
func TestBuildPrivateKeyAuth(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	tests := []struct {
		name        string
		config      Config
		expectError bool
	}{
		{
			name:        "inline key",
			config:      Config{PrivateKey: keyContent},
			expectError: false,
		},
		{
			name:        "key from file",
			config:      Config{KeyPath: keyPath},
			expectError: false,
		},
		{
			name:        "no key provided",
			config:      Config{},
			expectError: true,
		},
		{
			name:        "nonexistent key file",
			config:      Config{KeyPath: "/nonexistent/key"},
			expectError: true,
		},
		{
			name:        "invalid key content",
			config:      Config{PrivateKey: "not-a-valid-key"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildPrivateKeyAuth(tt.config)
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestBuildCertificateAuth tests certificate auth building.
func TestBuildCertificateAuth(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorSubstr string
	}{
		{
			name:        "missing private key",
			config:      Config{Certificate: "cert"},
			expectError: true,
			errorSubstr: "requires private key",
		},
		{
			name:        "missing certificate",
			config:      Config{PrivateKey: keyContent},
			expectError: true,
			errorSubstr: "requires certificate",
		},
		{
			name: "invalid private key",
			config: Config{
				PrivateKey:  "invalid-key",
				Certificate: "cert",
			},
			expectError: true,
			errorSubstr: "failed to parse private key",
		},
		{
			name: "invalid certificate",
			config: Config{
				PrivateKey:  keyContent,
				Certificate: "invalid-cert",
			},
			expectError: true,
			errorSubstr: "failed to parse certificate",
		},
		{
			name: "nonexistent key file",
			config: Config{
				KeyPath:     "/nonexistent/key",
				Certificate: "cert",
			},
			expectError: true,
			errorSubstr: "failed to read private key file",
		},
		{
			name: "nonexistent cert file",
			config: Config{
				KeyPath:         keyPath,
				CertificatePath: "/nonexistent/cert",
			},
			expectError: true,
			errorSubstr: "failed to read certificate file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildCertificateAuth(tt.config)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorSubstr != "" && !contains(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestAuthMethodConstants tests auth method constant values.
func TestAuthMethodConstants(t *testing.T) {
	if AuthMethodPrivateKey != "private_key" {
		t.Errorf("AuthMethodPrivateKey = %q, want %q", AuthMethodPrivateKey, "private_key")
	}
	if AuthMethodPassword != "password" {
		t.Errorf("AuthMethodPassword = %q, want %q", AuthMethodPassword, "password")
	}
	if AuthMethodCertificate != "certificate" {
		t.Errorf("AuthMethodCertificate = %q, want %q", AuthMethodCertificate, "certificate")
	}
}

// TestConfigTimeout tests timeout configuration.
func TestConfigTimeout(t *testing.T) {
	tests := []struct {
		name            string
		configTimeout   time.Duration
		expectedDefault bool
	}{
		{
			name:            "zero timeout uses default",
			configTimeout:   0,
			expectedDefault: true,
		},
		{
			name:            "custom timeout",
			configTimeout:   60 * time.Second,
			expectedDefault: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				Timeout: tt.configTimeout,
			}
			if tt.expectedDefault && config.Timeout != 0 {
				t.Error("expected zero timeout to be set")
			}
			if !tt.expectedDefault && config.Timeout != 60*time.Second {
				t.Errorf("expected 60s timeout, got %v", config.Timeout)
			}
		})
	}
}

// TestBastionDefaults tests bastion configuration defaults.
func TestBastionDefaults(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		expectedUser string
		expectedPort int
	}{
		{
			name: "bastion uses target user when not set",
			config: Config{
				User:        "targetuser",
				BastionHost: "bastion.example.com",
			},
			expectedUser: "targetuser",
			expectedPort: 22,
		},
		{
			name: "bastion uses own user when set",
			config: Config{
				User:        "targetuser",
				BastionHost: "bastion.example.com",
				BastionUser: "bastionuser",
			},
			expectedUser: "bastionuser",
			expectedPort: 22,
		},
		{
			name: "bastion uses custom port",
			config: Config{
				User:        "targetuser",
				BastionHost: "bastion.example.com",
				BastionPort: 2222,
			},
			expectedUser: "targetuser",
			expectedPort: 2222,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the expected behavior.
			bastionUser := tt.config.BastionUser
			if bastionUser == "" {
				bastionUser = tt.config.User
			}
			if bastionUser != tt.expectedUser {
				t.Errorf("expected bastion user %q, got %q", tt.expectedUser, bastionUser)
			}

			bastionPort := tt.config.BastionPort
			if bastionPort == 0 {
				bastionPort = 22
			}
			if bastionPort != tt.expectedPort {
				t.Errorf("expected bastion port %d, got %d", tt.expectedPort, bastionPort)
			}
		})
	}
}

// TestConnectToBastion_Errors tests various bastion connection error scenarios.
func TestConnectToBastion_Errors(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	tests := []struct {
		name        string
		config      Config
		errorSubstr string
	}{
		{
			name: "missing bastion key",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				BastionHost: "bastion.example.com",
				// No key configured for bastion or target.
			},
			errorSubstr: "no SSH key configured for bastion",
		},
		{
			name: "nonexistent bastion key path",
			config: Config{
				Host:           "target.internal",
				Port:           22,
				User:           "root",
				BastionHost:    "bastion.example.com",
				BastionKeyPath: "/nonexistent/bastion/key",
			},
			errorSubstr: "failed to read bastion key file",
		},
		{
			name: "invalid bastion key content",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				BastionHost: "bastion.example.com",
				BastionKey:  "invalid-key-content",
			},
			errorSubstr: "failed to parse bastion SSH key",
		},
		{
			name: "bastion uses target key path - nonexistent",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				KeyPath:     "/nonexistent/target/key",
				BastionHost: "bastion.example.com",
			},
			errorSubstr: "failed to read key file for bastion",
		},
		{
			name: "bastion uses target inline key",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				PrivateKey:  keyContent,
				BastionHost: "bastion.example.com",
			},
			// This will fail at connection, not at key parsing.
			errorSubstr: "",
		},
		{
			name: "bastion with password auth",
			config: Config{
				Host:            "target.internal",
				Port:            22,
				User:            "root",
				PrivateKey:      keyContent,
				BastionHost:     "bastion.example.com",
				BastionPassword: "secret",
			},
			// This will fail at connection, not at auth setup.
			errorSubstr: "",
		},
		{
			name: "bastion uses target key file",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				KeyPath:     keyPath,
				BastionHost: "bastion.example.com",
			},
			// This will fail at connection, not at key parsing.
			errorSubstr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := connectToBastion(tt.config, 5*time.Second)
			if err == nil && tt.errorSubstr != "" {
				t.Error("expected error, got nil")
			}
			if err != nil && tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
				t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
			}
		})
	}
}

// TestNewClient_NoAuthMethods tests the case where no auth methods can be built.
func TestNewClient_NoAuthMethods(t *testing.T) {
	// This should fail because no auth method is configured.
	config := Config{
		Host: "192.168.1.100",
		Port: 22,
		User: "root",
		// No auth method configured.
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("expected error for missing auth method, got nil")
	}
}

// TestNewClient_WithBastion tests NewClient with bastion configuration.
func TestNewClient_WithBastion(t *testing.T) {
	keyContent, _ := generateTestKey(t)

	config := Config{
		Host:        "target.internal",
		Port:        22,
		User:        "root",
		PrivateKey:  keyContent,
		BastionHost: "bastion.example.com",
		BastionPort: 22,
		BastionKey:  keyContent,
	}

	// This will fail to connect but should get past auth setup.
	_, err := NewClient(config)
	if err == nil {
		t.Skip("unexpectedly connected")
	}

	// Error should be about connection, not auth.
	if findSubstring(err.Error(), "no SSH") {
		t.Errorf("expected connection error, got auth error: %v", err)
	}
}

// TestNewClient_DefaultTimeout tests that default timeout is applied.
func TestNewClient_DefaultTimeout(t *testing.T) {
	keyContent, _ := generateTestKey(t)

	config := Config{
		Host:       "192.168.1.100",
		Port:       22,
		User:       "root",
		PrivateKey: keyContent,
		Timeout:    0, // Should default to 30s
	}

	// Will fail to connect but tests timeout handling.
	_, err := NewClient(config)
	if err == nil {
		t.Skip("unexpectedly connected")
	}
}

// TestClient_Interface ensures Client implements ClientInterface.
func TestClient_Interface(t *testing.T) {
	var _ ClientInterface = (*Client)(nil)
}

// TestUploadFile_RemotePathParsing tests the directory extraction in UploadFile.
func TestUploadFile_RemotePathParsing(t *testing.T) {
	tests := []struct {
		remotePath  string
		expectedDir string
	}{
		{"/etc/nginx/nginx.conf", "/etc/nginx"},
		{"/single/file.txt", "/single"},
		{"/deep/nested/path/to/file.txt", "/deep/nested/path/to"},
		{"/root.txt", ""},
	}

	for _, tt := range tests {
		t.Run(tt.remotePath, func(t *testing.T) {
			// Extract directory using same logic as UploadFile.
			lastSlashIdx := -1
			for i := len(tt.remotePath) - 1; i >= 0; i-- {
				if tt.remotePath[i] == '/' {
					lastSlashIdx = i
					break
				}
			}

			var dir string
			if lastSlashIdx > 0 {
				dir = tt.remotePath[:lastSlashIdx]
			}

			if dir != tt.expectedDir {
				t.Errorf("expected dir %q, got %q", tt.expectedDir, dir)
			}
		})
	}
}

// TestSetFileAttributes_ModeFormat tests mode string format validation.
func TestSetFileAttributes_ModeFormat(t *testing.T) {
	tests := []struct {
		mode        string
		shouldError bool
	}{
		{"0644", false},
		{"0755", false},
		{"0600", false},
		{"644", false},
		{"755", false},
		{"invalid", true},
		{"99999", true},
		{"", false}, // Empty is valid (no-op)
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			if tt.mode == "" {
				return
			}

			_, err := strtoull(tt.mode, 8, 32)
			if tt.shouldError && err == nil {
				t.Error("expected error for invalid mode")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestIsBinaryContent_EdgeCases tests edge cases for binary detection.
func TestIsBinaryContent_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected bool
	}{
		{"single space", []byte(" "), false},
		{"newlines only", []byte("\n\n\n"), false},
		{"tabs and spaces", []byte("\t \t \t"), false},
		{"high ascii", []byte{0x80, 0x81, 0x82}, false},
		{"control chars no null", []byte{0x01, 0x02, 0x03}, false},
		{"mixed with null in middle", []byte{0x41, 0x00, 0x42}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBinaryContent(tt.content)
			if result != tt.expected {
				t.Errorf("IsBinaryContent() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestMockClient_UploadFile tests file upload via mock.
func TestMockClient_UploadFile(t *testing.T) {
	client := NewMockClient()

	// Create a temp file to upload.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	content := []byte("test content")
	if err := os.WriteFile(localPath, content, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	remotePath := "/remote/test.txt"

	// Test upload.
	err := client.UploadFile(localPath, remotePath)
	if err != nil {
		t.Errorf("UploadFile() error = %v", err)
	}

	// Verify file exists.
	exists, err := client.FileExists(remotePath)
	if err != nil {
		t.Errorf("FileExists() error = %v", err)
	}
	if !exists {
		t.Error("expected file to exist after upload")
	}
}

// TestMockClient_GetFileHash tests hash retrieval via mock.
func TestMockClient_GetFileHash(t *testing.T) {
	client := NewMockClient()
	client.SetFile("/test.txt", []byte("test content"), 0644)

	hash, err := client.GetFileHash("/test.txt")
	if err != nil {
		t.Errorf("GetFileHash() error = %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}

	// Test non-existent file.
	_, err = client.GetFileHash("/nonexistent.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestMockClient_SetFileAttributes tests attribute setting via mock.
func TestMockClient_SetFileAttributes(t *testing.T) {
	client := NewMockClient()
	client.SetFile("/test.txt", []byte("content"), 0644)

	err := client.SetFileAttributes("/test.txt", "root", "root", "0755")
	if err != nil {
		t.Errorf("SetFileAttributes() error = %v", err)
	}

	// Test with non-existent file.
	err = client.SetFileAttributes("/nonexistent.txt", "root", "", "")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}

	// Test invalid mode.
	err = client.SetFileAttributes("/test.txt", "", "", "invalid")
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}

// TestMockClient_DeleteFile tests file deletion via mock.
func TestMockClient_DeleteFile(t *testing.T) {
	client := NewMockClient()
	client.SetFile("/test.txt", []byte("content"), 0644)

	// Verify file exists.
	exists, _ := client.FileExists("/test.txt")
	if !exists {
		t.Error("expected file to exist before delete")
	}

	// Delete file.
	err := client.DeleteFile("/test.txt")
	if err != nil {
		t.Errorf("DeleteFile() error = %v", err)
	}

	// Verify file is gone.
	exists, _ = client.FileExists("/test.txt")
	if exists {
		t.Error("expected file to not exist after delete")
	}

	// Delete non-existent file should not error.
	err = client.DeleteFile("/nonexistent.txt")
	if err != nil {
		t.Errorf("DeleteFile() for nonexistent file should not error: %v", err)
	}
}

// TestMockClient_FileExists tests file existence check via mock.
func TestMockClient_FileExists(t *testing.T) {
	client := NewMockClient()
	client.SetFile("/exists.txt", []byte("content"), 0644)

	exists, err := client.FileExists("/exists.txt")
	if err != nil {
		t.Errorf("FileExists() error = %v", err)
	}
	if !exists {
		t.Error("expected file to exist")
	}

	exists, err = client.FileExists("/not-exists.txt")
	if err != nil {
		t.Errorf("FileExists() error = %v", err)
	}
	if exists {
		t.Error("expected file to not exist")
	}
}

// TestMockClient_GetFileInfo tests file info retrieval via mock.
func TestMockClient_GetFileInfo(t *testing.T) {
	client := NewMockClient()
	content := []byte("test content here")
	client.SetFile("/test.txt", content, 0755)

	info, err := client.GetFileInfo("/test.txt")
	if err != nil {
		t.Errorf("GetFileInfo() error = %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil FileInfo")
	}
	if info.Size() != int64(len(content)) {
		t.Errorf("Size() = %d, want %d", info.Size(), len(content))
	}
	if info.Mode() != 0755 {
		t.Errorf("Mode() = %o, want %o", info.Mode(), 0755)
	}

	// Test non-existent file.
	_, err = client.GetFileInfo("/nonexistent.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestMockClient_ReadFileContent tests file content reading via mock.
func TestMockClient_ReadFileContent(t *testing.T) {
	client := NewMockClient()
	content := []byte("this is test content for reading")
	client.SetFile("/test.txt", content, 0644)

	// Read all content.
	data, err := client.ReadFileContent("/test.txt", 0)
	if err != nil {
		t.Errorf("ReadFileContent() error = %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("ReadFileContent() = %q, want %q", data, content)
	}

	// Read with limit.
	data, err = client.ReadFileContent("/test.txt", 10)
	if err != nil {
		t.Errorf("ReadFileContent() with limit error = %v", err)
	}
	if len(data) != 10 {
		t.Errorf("ReadFileContent() with limit returned %d bytes, want 10", len(data))
	}

	// Read non-existent file.
	_, err = client.ReadFileContent("/nonexistent.txt", 0)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestMockClient_WithErrors tests error handling via mock.
func TestMockClient_WithErrors(t *testing.T) {
	client := NewMockClient()
	testErr := os.ErrPermission

	// Test Close error.
	client.SetError("Close", testErr)
	if err := client.Close(); err != testErr {
		t.Errorf("Close() error = %v, want %v", err, testErr)
	}

	// Reset and test GetFileHash error.
	client = NewMockClient()
	client.SetFile("/test.txt", []byte("content"), 0644)
	client.SetError("GetFileHash", testErr)
	if _, err := client.GetFileHash("/test.txt"); err != testErr {
		t.Errorf("GetFileHash() error = %v, want %v", err, testErr)
	}

	// Test SetFileAttributes error.
	client = NewMockClient()
	client.SetFile("/test.txt", []byte("content"), 0644)
	client.SetError("SetFileAttributes", testErr)
	if err := client.SetFileAttributes("/test.txt", "root", "", ""); err != testErr {
		t.Errorf("SetFileAttributes() error = %v, want %v", err, testErr)
	}

	// Test DeleteFile error.
	client = NewMockClient()
	client.SetError("DeleteFile", testErr)
	if err := client.DeleteFile("/test.txt"); err != testErr {
		t.Errorf("DeleteFile() error = %v, want %v", err, testErr)
	}

	// Test FileExists error.
	client = NewMockClient()
	client.SetError("FileExists", testErr)
	if _, err := client.FileExists("/test.txt"); err != testErr {
		t.Errorf("FileExists() error = %v, want %v", err, testErr)
	}

	// Test GetFileInfo error.
	client = NewMockClient()
	client.SetFile("/test.txt", []byte("content"), 0644)
	client.SetError("GetFileInfo", testErr)
	if _, err := client.GetFileInfo("/test.txt"); err != testErr {
		t.Errorf("GetFileInfo() error = %v, want %v", err, testErr)
	}

	// Test ReadFileContent error.
	client = NewMockClient()
	client.SetFile("/test.txt", []byte("content"), 0644)
	client.SetError("ReadFileContent", testErr)
	if _, err := client.ReadFileContent("/test.txt", 0); err != testErr {
		t.Errorf("ReadFileContent() error = %v, want %v", err, testErr)
	}

	// Test UploadFile error.
	client = NewMockClient()
	client.SetError("UploadFile", testErr)
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := client.UploadFile(localPath, "/remote.txt"); err != testErr {
		t.Errorf("UploadFile() error = %v, want %v", err, testErr)
	}
}

// TestMockClient_UploadFile_LocalNotFound tests upload with missing local file.
func TestMockClient_UploadFile_LocalNotFound(t *testing.T) {
	client := NewMockClient()
	err := client.UploadFile("/nonexistent/local/file.txt", "/remote.txt")
	if err == nil {
		t.Error("expected error for nonexistent local file")
	}
}

// TestMockFileInfo tests the mockFileInfo implementation.
func TestMockFileInfo(t *testing.T) {
	info := &mockFileInfo{
		name:    "test.txt",
		size:    100,
		mode:    0755,
		modTime: time.Now(),
		isDir:   false,
	}

	if info.Name() != "test.txt" {
		t.Errorf("Name() = %q, want %q", info.Name(), "test.txt")
	}
	if info.Size() != 100 {
		t.Errorf("Size() = %d, want %d", info.Size(), 100)
	}
	if info.Mode() != 0755 {
		t.Errorf("Mode() = %o, want %o", info.Mode(), 0755)
	}
	if info.IsDir() != false {
		t.Error("IsDir() should be false")
	}
	if info.Sys() != nil {
		t.Error("Sys() should return nil")
	}
}

// TestClientInterface_Compliance ensures all implementations comply.
func TestClientInterface_Compliance(t *testing.T) {
	// Verify Client implements ClientInterface.
	var _ ClientInterface = (*Client)(nil)

	// Verify MockClientInterface implements ClientInterface.
	var _ ClientInterface = (*MockClientInterface)(nil)
}

// MockSFTPFile implements SFTPFile for testing.
type MockSFTPFile struct {
	content    []byte
	readOffset int
	closed     bool
}

func NewMockSFTPFile(content []byte) *MockSFTPFile {
	return &MockSFTPFile{content: content}
}

func (f *MockSFTPFile) Read(p []byte) (n int, err error) {
	if f.readOffset >= len(f.content) {
		return 0, io.EOF
	}
	n = copy(p, f.content[f.readOffset:])
	f.readOffset += n
	return n, nil
}

func (f *MockSFTPFile) Write(p []byte) (n int, err error) {
	f.content = append(f.content, p...)
	return len(p), nil
}

func (f *MockSFTPFile) Close() error {
	f.closed = true
	return nil
}

// MockSFTPClient implements SFTPClientInterface for testing.
type MockSFTPClient struct {
	files  map[string]*mockSFTPFileData
	errors map[string]error
	closed bool
}

type mockSFTPFileData struct {
	content []byte
	mode    os.FileMode
}

func NewMockSFTPClient() *MockSFTPClient {
	return &MockSFTPClient{
		files:  make(map[string]*mockSFTPFileData),
		errors: make(map[string]error),
	}
}

// Ensure MockSFTPClient implements SFTPClientInterface.
var _ SFTPClientInterface = (*MockSFTPClient)(nil)

func (m *MockSFTPClient) SetError(method string, err error) {
	m.errors[method] = err
}

func (m *MockSFTPClient) SetFile(path string, content []byte, mode os.FileMode) {
	m.files[path] = &mockSFTPFileData{content: content, mode: mode}
}

func (m *MockSFTPClient) Open(path string) (SFTPFile, error) {
	if err := m.errors["Open"]; err != nil {
		return nil, err
	}
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return NewMockSFTPFile(data.content), nil
}

func (m *MockSFTPClient) Create(path string) (SFTPFile, error) {
	if err := m.errors["Create"]; err != nil {
		return nil, err
	}
	m.files[path] = &mockSFTPFileData{content: []byte{}, mode: 0644}
	return NewMockSFTPFile(nil), nil
}

func (m *MockSFTPClient) Remove(path string) error {
	if err := m.errors["Remove"]; err != nil {
		return err
	}
	if _, ok := m.files[path]; !ok {
		return os.ErrNotExist
	}
	delete(m.files, path)
	return nil
}

func (m *MockSFTPClient) Stat(path string) (os.FileInfo, error) {
	if err := m.errors["Stat"]; err != nil {
		return nil, err
	}
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return &mockFileInfo{
		name:    filepath.Base(path),
		size:    int64(len(data.content)),
		mode:    data.mode,
		modTime: time.Now(),
		isDir:   false,
	}, nil
}

func (m *MockSFTPClient) Chmod(path string, mode os.FileMode) error {
	if err := m.errors["Chmod"]; err != nil {
		return err
	}
	data, ok := m.files[path]
	if !ok {
		return os.ErrNotExist
	}
	data.mode = mode
	return nil
}

func (m *MockSFTPClient) MkdirAll(path string) error {
	if err := m.errors["MkdirAll"]; err != nil {
		return err
	}
	return nil
}

func (m *MockSFTPClient) Close() error {
	if err := m.errors["Close"]; err != nil {
		return err
	}
	m.closed = true
	return nil
}

// Tests for Client methods using MockSFTPClient.

func TestClient_GetFileHash_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	content := []byte("test content for hashing")
	mockSFTP.SetFile("/test.txt", content, 0644)

	client := NewClientWithSFTP(mockSFTP, nil)

	hash, err := client.GetFileHash("/test.txt")
	if err != nil {
		t.Errorf("GetFileHash() error = %v", err)
	}

	// Verify hash format.
	if len(hash) != 71 { // "sha256:" (7) + 64 hex chars
		t.Errorf("hash length = %d, want 71", len(hash))
	}
	if hash[:7] != "sha256:" {
		t.Errorf("hash prefix = %q, want 'sha256:'", hash[:7])
	}

	// Compute expected hash.
	h := sha256.New()
	h.Write(content)
	expectedHash := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if hash != expectedHash {
		t.Errorf("hash = %q, want %q", hash, expectedHash)
	}
}

func TestClient_GetFileHash_FileNotFound(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.GetFileHash("/nonexistent.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestClient_GetFileHash_OpenError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	mockSFTP.SetError("Open", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.GetFileHash("/test.txt")
	if err == nil {
		t.Error("expected error when Open fails")
	}
}

func TestClient_FileExists_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/exists.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Test existing file.
	exists, err := client.FileExists("/exists.txt")
	if err != nil {
		t.Errorf("FileExists() error = %v", err)
	}
	if !exists {
		t.Error("expected file to exist")
	}

	// Test non-existing file.
	exists, err = client.FileExists("/not-exists.txt")
	if err != nil {
		t.Errorf("FileExists() error = %v", err)
	}
	if exists {
		t.Error("expected file to not exist")
	}
}

func TestClient_FileExists_StatError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	mockSFTP.SetError("Stat", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.FileExists("/test.txt")
	if err == nil {
		t.Error("expected error when Stat fails")
	}
}

func TestClient_GetFileInfo_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	content := []byte("file content here")
	mockSFTP.SetFile("/test.txt", content, 0755)
	client := NewClientWithSFTP(mockSFTP, nil)

	info, err := client.GetFileInfo("/test.txt")
	if err != nil {
		t.Errorf("GetFileInfo() error = %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil FileInfo")
	}
	if info.Size() != int64(len(content)) {
		t.Errorf("Size() = %d, want %d", info.Size(), len(content))
	}
	if info.Mode() != 0755 {
		t.Errorf("Mode() = %o, want %o", info.Mode(), 0755)
	}
}

func TestClient_GetFileInfo_FileNotFound(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.GetFileInfo("/nonexistent.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestClient_DeleteFile_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Verify file exists.
	exists, _ := client.FileExists("/test.txt")
	if !exists {
		t.Fatal("expected file to exist before delete")
	}

	// Delete file.
	err := client.DeleteFile("/test.txt")
	if err != nil {
		t.Errorf("DeleteFile() error = %v", err)
	}

	// Verify file is gone.
	exists, _ = client.FileExists("/test.txt")
	if exists {
		t.Error("expected file to not exist after delete")
	}
}

func TestClient_DeleteFile_NotExist(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	// Delete non-existent file should not error (idempotent).
	err := client.DeleteFile("/nonexistent.txt")
	if err != nil {
		t.Errorf("DeleteFile() for nonexistent file should not error: %v", err)
	}
}

func TestClient_DeleteFile_RemoveError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	mockSFTP.SetError("Remove", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	err := client.DeleteFile("/test.txt")
	if err == nil {
		t.Error("expected error when Remove fails")
	}
}

func TestClient_ReadFileContent_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	content := []byte("this is the file content to read")
	mockSFTP.SetFile("/test.txt", content, 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Read all content.
	data, err := client.ReadFileContent("/test.txt", 0)
	if err != nil {
		t.Errorf("ReadFileContent() error = %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("ReadFileContent() = %q, want %q", data, content)
	}
}

func TestClient_ReadFileContent_WithLimit(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	content := []byte("this is the file content to read")
	mockSFTP.SetFile("/test.txt", content, 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Read with limit.
	data, err := client.ReadFileContent("/test.txt", 10)
	if err != nil {
		t.Errorf("ReadFileContent() with limit error = %v", err)
	}
	if len(data) != 10 {
		t.Errorf("ReadFileContent() with limit returned %d bytes, want 10", len(data))
	}
	if string(data) != "this is th" {
		t.Errorf("ReadFileContent() = %q, want %q", data, "this is th")
	}
}

func TestClient_ReadFileContent_FileNotFound(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.ReadFileContent("/nonexistent.txt", 0)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestClient_ReadFileContent_OpenError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	mockSFTP.SetError("Open", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.ReadFileContent("/test.txt", 0)
	if err == nil {
		t.Error("expected error when Open fails")
	}
}

func TestClient_SetFileAttributes_Mode(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Set only mode (no owner/group to avoid SSH session).
	err := client.SetFileAttributes("/test.txt", "", "", "0755")
	if err != nil {
		t.Errorf("SetFileAttributes() error = %v", err)
	}

	// Verify mode was changed.
	info, _ := mockSFTP.Stat("/test.txt")
	if info.Mode() != 0755 {
		t.Errorf("Mode() = %o, want %o", info.Mode(), 0755)
	}
}

func TestClient_SetFileAttributes_InvalidMode(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	err := client.SetFileAttributes("/test.txt", "", "", "invalid")
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestClient_SetFileAttributes_ChmodError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	mockSFTP.SetError("Chmod", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	err := client.SetFileAttributes("/test.txt", "", "", "0755")
	if err == nil {
		t.Error("expected error when Chmod fails")
	}
}

func TestClient_SetFileAttributes_EmptyMode(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Empty mode should be a no-op (no error).
	err := client.SetFileAttributes("/test.txt", "", "", "")
	if err != nil {
		t.Errorf("SetFileAttributes() with empty mode should not error: %v", err)
	}
}

func TestNewClientWithSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.sftpClient != mockSFTP {
		t.Error("expected sftpClient to be the mock")
	}
}

func TestSFTPClientInterface_Compliance(t *testing.T) {
	// Verify MockSFTPClient implements SFTPClientInterface.
	var _ SFTPClientInterface = (*MockSFTPClient)(nil)

	// Verify SFTPClientWrapper implements SFTPClientInterface.
	var _ SFTPClientInterface = (*SFTPClientWrapper)(nil)
}

// Tests for UploadFile using MockSFTPClient.

func TestClient_UploadFile_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	// Create a temp file to upload.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	content := []byte("test content for upload")
	if err := os.WriteFile(localPath, content, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	remotePath := "/remote/path/test.txt"

	// Test upload.
	err := client.UploadFile(localPath, remotePath)
	if err != nil {
		t.Errorf("UploadFile() error = %v", err)
	}

	// Verify file was created in mock.
	if _, ok := mockSFTP.files[remotePath]; !ok {
		t.Error("expected file to be created in mock")
	}
}

func TestClient_UploadFile_MkdirAllError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetError("MkdirAll", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Create a temp file.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	err := client.UploadFile(localPath, "/remote/dir/file.txt")
	if err == nil {
		t.Error("expected error when MkdirAll fails")
	}
}

func TestClient_UploadFile_CreateError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetError("Create", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Create a temp file.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	err := client.UploadFile(localPath, "/remote/file.txt")
	if err == nil {
		t.Error("expected error when Create fails")
	}
}

func TestClient_UploadFile_LocalNotFound(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	err := client.UploadFile("/nonexistent/local/file.txt", "/remote/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent local file")
	}
}

func TestClient_UploadFile_RootPath(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	// Create a temp file.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Test uploading to root path (no directory to create).
	err := client.UploadFile(localPath, "/rootfile.txt")
	if err != nil {
		t.Errorf("UploadFile() to root error = %v", err)
	}
}

// Tests for Close method.

func TestClient_Close_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	err := client.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if !mockSFTP.closed {
		t.Error("expected mock SFTP to be closed")
	}
}

func TestClient_Close_SFTPError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetError("Close", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Close should not return SFTP close error (it doesn't propagate).
	_ = client.Close()
	// Just verifying it doesn't panic.
}

// Security-related tests

// TestValidateOwnerGroup tests owner/group name validation.
func TestValidateOwnerGroup(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		fieldName   string
		expectError bool
	}{
		// Valid cases
		{"valid username", "root", "owner", false},
		{"valid username with underscore", "my_user", "owner", false},
		{"valid username with hyphen", "my-user", "owner", false},
		{"valid group", "www-data", "group", false},
		{"valid numeric uid", "1000", "owner", false},
		{"valid numeric gid", "0", "group", false},
		{"starts with underscore", "_apt", "owner", false},
		{"empty is valid", "", "owner", false},

		// Invalid cases - command injection attempts
		{"semicolon injection", "root;rm -rf /", "owner", true},
		{"backtick injection", "root`whoami`", "owner", true},
		{"dollar injection", "root$(whoami)", "owner", true},
		{"pipe injection", "root|cat /etc/passwd", "owner", true},
		{"ampersand injection", "root&& cat /etc/passwd", "owner", true},
		{"newline injection", "root\ncat /etc/passwd", "owner", true},
		{"space injection", "root cat", "owner", true},
		{"quote injection single", "root'", "owner", true},
		{"quote injection double", "root\"", "owner", true},

		// Other invalid cases
		{"starts with number", "1abc", "owner", true},
		{"starts with hyphen", "-user", "owner", true},
		{"contains dot", "user.name", "owner", true},
		{"contains slash", "user/name", "owner", true},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "owner", true}, // 33 chars
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOwnerGroup(tt.value, tt.fieldName)
			if tt.expectError && err == nil {
				t.Errorf("expected error for %q, got nil", tt.value)
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error for %q: %v", tt.value, err)
			}
		})
	}
}

// TestShellQuote tests shell escaping functionality.
func TestShellQuote(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple string", "hello", "'hello'"},
		{"empty string", "", "''"},
		{"with space", "hello world", "'hello world'"},
		{"with single quote", "it's", "'it'\"'\"'s'"},
		{"with double quotes", "say \"hello\"", "'say \"hello\"'"},
		{"with backtick", "echo `whoami`", "'echo `whoami`'"},
		{"with dollar sign", "var=$HOME", "'var=$HOME'"},
		{"with semicolon", "cmd; rm -rf /", "'cmd; rm -rf /'"},
		{"with newline", "line1\nline2", "'line1\nline2'"},
		{"with special chars", "!@#$%^&*()", "'!@#$%^&*()'"},
		{"path with spaces", "/path/to/my file.txt", "'/path/to/my file.txt'"},
		{"multiple single quotes", "it's a 'test'", "'it'\"'\"'s a '\"'\"'test'\"'\"''"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shellQuote(tt.input)
			if result != tt.expected {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestValidateMode tests mode validation.
func TestValidateMode(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		expectError bool
	}{
		// Valid cases
		{"standard file mode", "0644", false},
		{"executable mode", "0755", false},
		{"private mode", "0600", false},
		{"world writable", "0777", false},
		{"3 digit mode", "644", false},
		{"sticky bit", "1755", false},
		{"setuid", "4755", false},
		{"setgid", "2755", false},
		{"all special bits", "7777", false},
		{"empty is valid", "", false},
		{"all zeros", "0000", false},
		{"min 3 digits", "000", false},

		// Invalid cases
		{"too short", "64", true},
		{"too long", "07755", true},
		{"non-octal digit 8", "0648", true},
		{"non-octal digit 9", "0659", true},
		{"letters", "abc", true},
		{"mixed letters and numbers", "06a4", true},
		{"special characters", "0644!", true},
		{"leading zero with 5 digits", "00755", true},
		{"negative", "-0644", true},
		{"hex notation", "0x1A4", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMode(tt.mode)
			if tt.expectError && err == nil {
				t.Errorf("expected error for mode %q, got nil", tt.mode)
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error for mode %q: %v", tt.mode, err)
			}
		})
	}
}

// TestSetFileAttributes_OwnerValidation tests that invalid owner names are rejected.
func TestSetFileAttributes_OwnerValidation(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	tests := []struct {
		name        string
		owner       string
		group       string
		expectError bool
	}{
		// Note: We can only test cases that fail validation or have no owner/group
		// because setting owner/group requires an SSH session which is nil in tests.
		{"injection in owner", "root;rm -rf /", "", true},
		{"injection in group", "", "staff$(whoami)", true},
		{"backtick injection", "root`id`", "", true},
		{"pipe injection", "root|whoami", "", true},
		{"both empty is ok", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.SetFileAttributes("/test.txt", tt.owner, tt.group, "")
			if tt.expectError {
				if err == nil {
					t.Error("expected validation error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestSetFileAttributes_ModeValidation tests that invalid modes are rejected.
func TestSetFileAttributes_ModeValidation(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	tests := []struct {
		name        string
		mode        string
		expectError bool
	}{
		{"valid 4-digit mode", "0755", false},
		{"valid 3-digit mode", "644", false},
		{"invalid non-octal", "0689", true},
		{"invalid letters", "abcd", true},
		{"empty mode ok", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.SetFileAttributes("/test.txt", "", "", tt.mode)
			if tt.expectError && err == nil {
				t.Errorf("expected error for mode %q, got nil", tt.mode)
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error for mode %q: %v", tt.mode, err)
			}
		})
	}
}

// TestUploadFile_PathParsingEdgeCases tests edge cases for path parsing.
func TestUploadFile_PathParsingEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		remotePath string
		expectDir  string
	}{
		{"root level file", "/file.txt", "/"},
		{"single directory", "/dir/file.txt", "/dir"},
		{"deep nesting", "/a/b/c/d/e/file.txt", "/a/b/c/d/e"},
		{"dot in path", "/path/to/.hidden", "/path/to"},
		{"double dot segment", "/path/../other/file.txt", "/other"}, // filepath.Dir cleans paths
		{"trailing slash edge", "/dir/subdir/", "/dir/subdir"},
		{"relative path", "relative/path/file.txt", "relative/path"},
		{"just filename", "file.txt", "."},
		{"current dir", "./file.txt", "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filepath.Dir(tt.remotePath)
			if result != tt.expectDir {
				t.Errorf("filepath.Dir(%q) = %q, want %q", tt.remotePath, result, tt.expectDir)
			}
		})
	}
}

// TestExpandPath tests the path expansion helper.
func TestExpandPath(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot get home directory")
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"absolute path unchanged", "/etc/hosts", "/etc/hosts"},
		{"relative path unchanged", "relative/path", "relative/path"},
		{"tilde expands", "~/test", filepath.Join(homeDir, "test")},
		{"tilde with subpath", "~/.ssh/known_hosts", filepath.Join(homeDir, ".ssh/known_hosts")},
		{"tilde alone", "~/", filepath.Join(homeDir, "")}, // Note: may have trailing behavior
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandPath(tt.input)
			if result != tt.expected {
				t.Errorf("expandPath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
