package provider

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/darshan-rambhia/gosftp"
)

// MockSSHClient is a mock implementation of gosftp.ClientInterface for testing.
type MockSSHClient struct {
	// Synchronization.
	mu sync.Mutex

	// Configuration.
	UploadedFiles  map[string]string // remotePath -> localPath
	FileHashes     map[string]string // remotePath -> hash
	FileContents   map[string][]byte // remotePath -> content
	FileAttributes map[string]FileAttrs
	DeletedFiles   []string
	ExistingFiles  map[string]bool

	// Error controls.
	UploadError       error
	GetHashError      error
	SetAttributeError error
	DeleteError       error
	ExistsError       error
	ReadContentError  error

	// Call tracking.
	UploadCalls       int
	GetHashCalls      int
	SetAttributeCalls int
	DeleteCalls       int
	CloseCalled       bool
}

// FileAttrs holds file attributes for mock.
type FileAttrs struct {
	Owner string
	Group string
	Mode  string
}

// NewMockSSHClient creates a new mock SSH client.
func NewMockSSHClient() *MockSSHClient {
	return &MockSSHClient{
		UploadedFiles:  make(map[string]string),
		FileHashes:     make(map[string]string),
		FileContents:   make(map[string][]byte),
		FileAttributes: make(map[string]FileAttrs),
		ExistingFiles:  make(map[string]bool),
	}
}

// Close implements gosftp.ClientInterface.
func (m *MockSSHClient) Close() error {
	m.CloseCalled = true
	return nil
}

// UploadFile implements gosftp.ClientInterface.
func (m *MockSSHClient) UploadFile(ctx context.Context, localPath, remotePath string) error {
	m.mu.Lock()
	m.UploadCalls++
	if m.UploadError != nil {
		m.mu.Unlock()
		return m.UploadError
	}
	m.UploadedFiles[remotePath] = localPath
	m.ExistingFiles[remotePath] = true
	m.mu.Unlock()

	// Read local file content and compute hash.
	content, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.FileContents[remotePath] = content
	m.mu.Unlock()

	return nil
}

// GetFileHash implements gosftp.ClientInterface.
func (m *MockSSHClient) GetFileHash(ctx context.Context, remotePath string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetHashCalls++
	if m.GetHashError != nil {
		return "", m.GetHashError
	}
	hash, ok := m.FileHashes[remotePath]
	if !ok {
		return "", fmt.Errorf("file not found: %s", remotePath)
	}
	return hash, nil
}

// SetFileAttributes implements gosftp.ClientInterface.
func (m *MockSSHClient) SetFileAttributes(ctx context.Context, remotePath, owner, group, mode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.SetAttributeCalls++
	if m.SetAttributeError != nil {
		return m.SetAttributeError
	}
	m.FileAttributes[remotePath] = FileAttrs{
		Owner: owner,
		Group: group,
		Mode:  mode,
	}
	return nil
}

// DeleteFile implements gosftp.ClientInterface.
func (m *MockSSHClient) DeleteFile(ctx context.Context, remotePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DeleteCalls++
	if m.DeleteError != nil {
		return m.DeleteError
	}
	m.DeletedFiles = append(m.DeletedFiles, remotePath)
	delete(m.ExistingFiles, remotePath)
	delete(m.FileHashes, remotePath)
	delete(m.FileContents, remotePath)
	return nil
}

// FileExists implements gosftp.ClientInterface.
func (m *MockSSHClient) FileExists(ctx context.Context, remotePath string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ExistsError != nil {
		return false, m.ExistsError
	}
	return m.ExistingFiles[remotePath], nil
}

// GetFileInfo implements gosftp.ClientInterface.
func (m *MockSSHClient) GetFileInfo(ctx context.Context, remotePath string) (os.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.ExistingFiles[remotePath] {
		return nil, os.ErrNotExist
	}
	// Return a mock FileInfo - for testing we don't need full implementation.
	return nil, nil
}

// ReadFileContent implements gosftp.ClientInterface.
func (m *MockSSHClient) ReadFileContent(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ReadContentError != nil {
		return nil, m.ReadContentError
	}
	content, ok := m.FileContents[remotePath]
	if !ok {
		return nil, fmt.Errorf("file not found: %s", remotePath)
	}
	if maxBytes > 0 && int64(len(content)) > maxBytes {
		return content[:maxBytes], nil
	}
	return content, nil
}

// Ensure MockSSHClient implements gosftp.ClientInterface.
var _ gosftp.ClientInterface = (*MockSSHClient)(nil)

// MockSSHClientFactory creates a factory function that returns the given mock client.
func MockSSHClientFactory(mock *MockSSHClient) SSHClientFactory {
	return func(config gosftp.Config) (gosftp.ClientInterface, error) {
		return mock, nil
	}
}

// MockSSHClientFactoryWithError creates a factory function that returns an error.
func MockSSHClientFactoryWithError(err error) SSHClientFactory {
	return func(config gosftp.Config) (gosftp.ClientInterface, error) {
		return nil, err
	}
}
