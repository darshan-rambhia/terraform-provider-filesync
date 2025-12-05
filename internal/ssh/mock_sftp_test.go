package ssh

import (
	"io/fs"
	"os"
	"time"
)

// mockFileInfo implements os.FileInfo for testing.
type mockFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return m.size }
func (m *mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m *mockFileInfo) ModTime() time.Time { return m.modTime }
func (m *mockFileInfo) IsDir() bool        { return m.isDir }
func (m *mockFileInfo) Sys() any           { return nil }

// MockClientInterface provides a testable client implementation.
type MockClientInterface struct {
	files       map[string][]byte
	modes       map[string]os.FileMode
	owners      map[string]string
	groups      map[string]string
	shouldError map[string]error
}

// NewMockClient creates a new mock client for testing.
func NewMockClient() *MockClientInterface {
	return &MockClientInterface{
		files:       make(map[string][]byte),
		modes:       make(map[string]os.FileMode),
		owners:      make(map[string]string),
		groups:      make(map[string]string),
		shouldError: make(map[string]error),
	}
}

func (m *MockClientInterface) SetFile(path string, content []byte, mode os.FileMode) {
	m.files[path] = content
	m.modes[path] = mode
}

func (m *MockClientInterface) SetError(op string, err error) {
	m.shouldError[op] = err
}

func (m *MockClientInterface) Close() error {
	if err, ok := m.shouldError["Close"]; ok {
		return err
	}
	return nil
}

func (m *MockClientInterface) UploadFile(localPath, remotePath string) error {
	if err, ok := m.shouldError["UploadFile"]; ok {
		return err
	}

	content, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}

	m.files[remotePath] = content
	m.modes[remotePath] = 0644
	return nil
}

func (m *MockClientInterface) GetFileHash(remotePath string) (string, error) {
	if err, ok := m.shouldError["GetFileHash"]; ok {
		return "", err
	}

	content, exists := m.files[remotePath]
	if !exists {
		return "", os.ErrNotExist
	}

	return hashContent(content), nil
}

func (m *MockClientInterface) SetFileAttributes(remotePath, owner, group, mode string) error {
	if err, ok := m.shouldError["SetFileAttributes"]; ok {
		return err
	}

	if _, exists := m.files[remotePath]; !exists {
		return os.ErrNotExist
	}

	if owner != "" {
		m.owners[remotePath] = owner
	}
	if group != "" {
		m.groups[remotePath] = group
	}
	if mode != "" {
		modeInt, err := parseOctal(mode)
		if err != nil {
			return err
		}
		m.modes[remotePath] = os.FileMode(modeInt)
	}

	return nil
}

func (m *MockClientInterface) DeleteFile(remotePath string) error {
	if err, ok := m.shouldError["DeleteFile"]; ok {
		return err
	}

	if _, exists := m.files[remotePath]; !exists {
		return nil // Already deleted
	}

	delete(m.files, remotePath)
	delete(m.modes, remotePath)
	delete(m.owners, remotePath)
	delete(m.groups, remotePath)
	return nil
}

func (m *MockClientInterface) FileExists(remotePath string) (bool, error) {
	if err, ok := m.shouldError["FileExists"]; ok {
		return false, err
	}

	_, exists := m.files[remotePath]
	return exists, nil
}

func (m *MockClientInterface) GetFileInfo(remotePath string) (os.FileInfo, error) {
	if err, ok := m.shouldError["GetFileInfo"]; ok {
		return nil, err
	}

	content, exists := m.files[remotePath]
	if !exists {
		return nil, os.ErrNotExist
	}

	mode := m.modes[remotePath]
	if mode == 0 {
		mode = 0644
	}

	return &mockFileInfo{
		name:    remotePath,
		size:    int64(len(content)),
		mode:    mode,
		modTime: time.Now(),
		isDir:   false,
	}, nil
}

func (m *MockClientInterface) ReadFileContent(remotePath string, maxBytes int64) ([]byte, error) {
	if err, ok := m.shouldError["ReadFileContent"]; ok {
		return nil, err
	}

	content, exists := m.files[remotePath]
	if !exists {
		return nil, os.ErrNotExist
	}

	if maxBytes > 0 && int64(len(content)) > maxBytes {
		return content[:maxBytes], nil
	}

	return content, nil
}

// Helper functions.
func hashContent(content []byte) string {
	// Simplified hash for testing.
	return "sha256:mock_hash_" + string(content[:min(10, len(content))])
}

func parseOctal(s string) (uint64, error) {
	var val uint64
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, fs.ErrInvalid
		}
		val = val*8 + uint64(c-'0')
	}
	return val, nil
}

// Verify MockClientInterface implements ClientInterface.
var _ ClientInterface = (*MockClientInterface)(nil)
