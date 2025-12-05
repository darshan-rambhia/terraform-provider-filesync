package provider

import (
	"fmt"
	"os"

	"github.com/darshan-rambhia/terraform-provider-filesync/internal/ssh"
)

// MockSSHClient is a mock implementation of ssh.ClientInterface for testing.
type MockSSHClient struct {
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

// Close implements ssh.ClientInterface.
func (m *MockSSHClient) Close() error {
	m.CloseCalled = true
	return nil
}

// UploadFile implements ssh.ClientInterface.
func (m *MockSSHClient) UploadFile(localPath, remotePath string) error {
	m.UploadCalls++
	if m.UploadError != nil {
		return m.UploadError
	}
	m.UploadedFiles[remotePath] = localPath
	m.ExistingFiles[remotePath] = true

	// Read local file content and compute hash.
	content, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	m.FileContents[remotePath] = content

	return nil
}

// GetFileHash implements ssh.ClientInterface.
func (m *MockSSHClient) GetFileHash(remotePath string) (string, error) {
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

// SetFileAttributes implements ssh.ClientInterface.
func (m *MockSSHClient) SetFileAttributes(remotePath, owner, group, mode string) error {
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

// DeleteFile implements ssh.ClientInterface.
func (m *MockSSHClient) DeleteFile(remotePath string) error {
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

// FileExists implements ssh.ClientInterface.
func (m *MockSSHClient) FileExists(remotePath string) (bool, error) {
	if m.ExistsError != nil {
		return false, m.ExistsError
	}
	return m.ExistingFiles[remotePath], nil
}

// GetFileInfo implements ssh.ClientInterface.
func (m *MockSSHClient) GetFileInfo(remotePath string) (os.FileInfo, error) {
	if !m.ExistingFiles[remotePath] {
		return nil, os.ErrNotExist
	}
	// Return a mock FileInfo - for testing we don't need full implementation.
	return nil, nil
}

// ReadFileContent implements ssh.ClientInterface.
func (m *MockSSHClient) ReadFileContent(remotePath string, maxBytes int64) ([]byte, error) {
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

// Ensure MockSSHClient implements ssh.ClientInterface.
var _ ssh.ClientInterface = (*MockSSHClient)(nil)

// MockSSHClientFactory creates a factory function that returns the given mock client.
func MockSSHClientFactory(mock *MockSSHClient) SSHClientFactory {
	return func(config ssh.Config) (ssh.ClientInterface, error) {
		return mock, nil
	}
}

// MockSSHClientFactoryWithError creates a factory function that returns an error.
func MockSSHClientFactoryWithError(err error) SSHClientFactory {
	return func(config ssh.Config) (ssh.ClientInterface, error) {
		return nil, err
	}
}
