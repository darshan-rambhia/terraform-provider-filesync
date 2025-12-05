package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darshan-rambhia/terraform-provider-filesync/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// ProtoV6ProviderFactories are used to instantiate a provider during.
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can reattach.
var ProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"filesync": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// TestSSHConfig holds SSH configuration for acceptance tests.
// This ensures provider, resource, and datasource configs stay in sync.
type TestSSHConfig struct {
	Host           string
	Port           int
	User           string
	PrivateKeyPath string
	PrivateKey     string // inline key content
	Owner          string
	Group          string
}

// NewTestSSHConfig creates a TestSSHConfig from an SSHTestContainer.
func NewTestSSHConfig(c *SSHTestContainer) *TestSSHConfig {
	return &TestSSHConfig{
		Host:           c.Host,
		Port:           c.Port,
		User:           c.User,
		PrivateKeyPath: c.PrivateKeyPath,
		PrivateKey:     c.PrivateKey,
		Owner:          c.User,
		Group:          c.User,
	}
}

// ProviderBlock returns the provider configuration block.
func (c *TestSSHConfig) ProviderBlock() string {
	if c.PrivateKey != "" {
		escapedKey := strings.ReplaceAll(c.PrivateKey, "\n", "\\n")
		return fmt.Sprintf(`
provider "filesync" {
  ssh_user        = %q
  ssh_private_key = %q
  ssh_port        = %d
}
`, c.User, escapedKey, c.Port)
	}
	return fmt.Sprintf(`
provider "filesync" {
  ssh_user     = %q
  ssh_key_path = %q
  ssh_port     = %d
}
`, c.User, c.PrivateKeyPath, c.Port)
}

// ProviderBlockWithPooling returns the provider configuration with connection pooling enabled.
func (c *TestSSHConfig) ProviderBlockWithPooling() string {
	if c.PrivateKey != "" {
		escapedKey := strings.ReplaceAll(c.PrivateKey, "\n", "\\n")
		return fmt.Sprintf(`
provider "filesync" {
  ssh_user                = %q
  ssh_private_key         = %q
  ssh_port                = %d
  connection_pool_enabled = true
}
`, c.User, escapedKey, c.Port)
	}
	return fmt.Sprintf(`
provider "filesync" {
  ssh_user                = %q
  ssh_key_path            = %q
  ssh_port                = %d
  connection_pool_enabled = true
}
`, c.User, c.PrivateKeyPath, c.Port)
}

// SSHAttributes returns common SSH attributes for resources/datasources.
func (c *TestSSHConfig) SSHAttributes() string {
	if c.PrivateKey != "" {
		escapedKey := strings.ReplaceAll(c.PrivateKey, "\n", "\\n")
		return fmt.Sprintf(`
  ssh_port        = %d
  ssh_private_key = %q
  ssh_user        = %q
`, c.Port, escapedKey, c.User)
	}
	return fmt.Sprintf(`
  ssh_port     = %d
  ssh_key_path = %q
  ssh_user     = %q
`, c.Port, c.PrivateKeyPath, c.User)
}

// OwnerAttributes returns owner/group attributes for resources.
func (c *TestSSHConfig) OwnerAttributes() string {
	return fmt.Sprintf(`
  owner = %q
  group = %q
`, c.Owner, c.Group)
}

// FileResourceConfig generates a complete filesync_file resource config.
func (c *TestSSHConfig) FileResourceConfig(name, source, destination, mode string) string {
	return fmt.Sprintf(`%s
resource "filesync_file" %q {
  source      = %q
  destination = %q
  host        = %q
  mode        = %q
%s%s}
`, c.ProviderBlock(), name, source, destination, c.Host, mode, c.SSHAttributes(), c.OwnerAttributes())
}

// FileResourceConfigWithPooling generates a filesync_file resource config with connection pooling.
func (c *TestSSHConfig) FileResourceConfigWithPooling(name, source, destination, mode string) string {
	return fmt.Sprintf(`%s
resource "filesync_file" %q {
  source      = %q
  destination = %q
  host        = %q
  mode        = %q
%s%s}
`, c.ProviderBlockWithPooling(), name, source, destination, c.Host, mode, c.SSHAttributes(), c.OwnerAttributes())
}

// MultipleFileResourcesWithPooling generates multiple file resources with connection pooling enabled.
func (c *TestSSHConfig) MultipleFileResourcesWithPooling(files []struct{ Name, Source, Destination, Mode string }) string {
	config := c.ProviderBlockWithPooling()
	for _, f := range files {
		config += fmt.Sprintf(`
resource "filesync_file" %q {
  source      = %q
  destination = %q
  host        = %q
  mode        = %q
%s%s}
`, f.Name, f.Source, f.Destination, c.Host, f.Mode, c.SSHAttributes(), c.OwnerAttributes())
	}
	return config
}

// DirectoryResourceConfig generates a complete filesync_directory resource config.
func (c *TestSSHConfig) DirectoryResourceConfig(name, source, destination, mode string, excludes []string) string {
	excludeBlock := ""
	if len(excludes) > 0 {
		excludeList := ""
		for _, e := range excludes {
			excludeList += fmt.Sprintf("    %q,\n", e)
		}
		excludeBlock = fmt.Sprintf("  exclude = [\n%s  ]\n", excludeList)
	}

	return fmt.Sprintf(`%s
resource "filesync_directory" %q {
  source      = %q
  destination = %q
  host        = %q
  mode        = %q
%s%s%s}
`, c.ProviderBlock(), name, source, destination, c.Host, mode, c.SSHAttributes(), c.OwnerAttributes(), excludeBlock)
}

// HostDataSourceConfig generates a complete filesync_host datasource config.
func (c *TestSSHConfig) HostDataSourceConfig(name string) string {
	return fmt.Sprintf(`%s
data "filesync_host" %q {
  address = %q
%s}
`, c.ProviderBlock(), name, c.Host, c.SSHAttributes())
}

// ProviderOnlyConfig returns just the provider block (for destroy tests).
func (c *TestSSHConfig) ProviderOnlyConfig() string {
	return c.ProviderBlock()
}

// FileResourceConfigWithInlineKey generates a filesync_file resource config using inline SSH key.
func (c *TestSSHConfig) FileResourceConfigWithInlineKey(name, source, destination, mode string) string {
	escapedKey := strings.ReplaceAll(c.PrivateKey, "\n", "\\n")
	return fmt.Sprintf(`
provider "filesync" {
  ssh_user        = %q
  ssh_private_key = %q
  ssh_port        = %d
}

resource "filesync_file" %q {
  source          = %q
  destination     = %q
  host            = %q
  mode            = %q
  ssh_port        = %d
  ssh_private_key = %q
  ssh_user        = %q
  owner           = %q
  group           = %q
}
`, c.User, escapedKey, c.Port, name, source, destination, c.Host, mode, c.Port, escapedKey, c.User, c.Owner, c.Group)
}

// HostDataSourceWithFileConfig generates a config that tests datasource with file resource using it.
func (c *TestSSHConfig) HostDataSourceWithFileConfig(sourceFile, remotePath string) string {
	return fmt.Sprintf(`
provider "filesync" {}

data "filesync_host" "test" {
  address      = %q
  ssh_user     = %q
  ssh_key_path = %q
  ssh_port     = %d
}

resource "filesync_file" "test" {
  source      = %q
  destination = %q
  host        = data.filesync_host.test.address

  ssh_user     = data.filesync_host.test.ssh_user
  ssh_key_path = data.filesync_host.test.ssh_key_path
  ssh_port     = data.filesync_host.test.ssh_port
  mode         = "0644"
}
`, c.Host, c.User, c.PrivateKeyPath, c.Port, sourceFile, remotePath)
}

// HostDataSourceForEachConfig generates a config that tests datasource with for_each.
func (c *TestSSHConfig) HostDataSourceForEachConfig(sourceFile string) string {
	return fmt.Sprintf(`
provider "filesync" {}

locals {
  servers = {
    server1 = "/tmp/server1.txt"
    server2 = "/tmp/server2.txt"
  }
}

data "filesync_host" "servers" {
  for_each = local.servers

  address      = %q
  ssh_user     = %q
  ssh_key_path = %q
  ssh_port     = %d
}

resource "filesync_file" "test" {
  for_each = data.filesync_host.servers

  source      = %q
  destination = local.servers[each.key]
  host        = each.value.address

  ssh_user     = each.value.ssh_user
  ssh_key_path = each.value.ssh_key_path
  ssh_port     = each.value.ssh_port
  mode         = "0644"
}
`, c.Host, c.User, c.PrivateKeyPath, c.Port, sourceFile)
}

// Test file creation helpers.

// CreateTestSourceFile creates a temporary file with the given content for testing.
func CreateTestSourceFile(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "source_file.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test source file: %v", err)
	}
	return path
}

// CreateTestSourceDirectory creates a temporary directory with test files.
func CreateTestSourceDirectory(t *testing.T, files map[string]string) string {
	t.Helper()
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("failed to create source directory: %v", err)
	}

	for path, content := range files {
		fullPath := filepath.Join(srcDir, path)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create file %s: %v", path, err)
		}
	}

	return srcDir
}

// CreateTestSourceFileBytes creates a temporary file with binary content for testing.
func CreateTestSourceFileBytes(t *testing.T, content []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "source_file.bin")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("failed to create test source file: %v", err)
	}
	return path
}

// Test check functions.

// CheckRemoteFileExists returns a TestCheckFunc that verifies a remote file exists.
func CheckRemoteFileExists(container *SSHTestContainer, path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if !container.FileExistsNoHelper(path) {
			return fmt.Errorf("remote file %s does not exist", path)
		}
		return nil
	}
}

// CheckRemoteFileNotExists returns a TestCheckFunc that verifies a remote file doesn't exist.
func CheckRemoteFileNotExists(container *SSHTestContainer, path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if container.FileExistsNoHelper(path) {
			return fmt.Errorf("remote file %s still exists", path)
		}
		return nil
	}
}

// CheckRemoteFileContent returns a TestCheckFunc that verifies remote file content.
func CheckRemoteFileContent(container *SSHTestContainer, path, expected string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		content, err := container.ReadRemoteFileNoHelper(path)
		if err != nil {
			return fmt.Errorf("failed to read remote file: %w", err)
		}
		if content != expected {
			return fmt.Errorf("remote file content mismatch:\n  expected: %q\n  got: %q", expected, content)
		}
		return nil
	}
}

// CheckRemoteFileMode returns a TestCheckFunc that verifies remote file permissions.
func CheckRemoteFileMode(container *SSHTestContainer, path, expected string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		mode, err := container.GetFileModeNoHelper(path)
		if err != nil {
			return fmt.Errorf("failed to get file mode: %w", err)
		}
		mode = strings.TrimSpace(mode)
		if mode != expected {
			return fmt.Errorf("remote file mode mismatch:\n  expected: %s\n  got: %s", expected, mode)
		}
		return nil
	}
}

// CheckRemoteFileSizeEquals returns a TestCheckFunc that verifies remote file size.
func CheckRemoteFileSizeEquals(container *SSHTestContainer, path string, expectedSize int64) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		output, err := container.runCommand(fmt.Sprintf("stat -c%%s %q", path))
		if err != nil {
			return fmt.Errorf("failed to get file size: %w", err)
		}
		var actualSize int64
		if _, err := fmt.Sscanf(strings.TrimSpace(output), "%d", &actualSize); err != nil {
			return fmt.Errorf("failed to parse file size: %w", err)
		}
		if actualSize != expectedSize {
			return fmt.Errorf("remote file size mismatch:\n  expected: %d\n  got: %d", expectedSize, actualSize)
		}
		return nil
	}
}

// CaptureHash returns a TestCheckFunc that captures the source_hash attribute.
func CaptureHash(resourceName string, hashPtr *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}
		*hashPtr = rs.Primary.Attributes["source_hash"]
		return nil
	}
}

// CheckHashChanged returns a TestCheckFunc that verifies the hash changed.
func CheckHashChanged(resourceName string, oldHashPtr *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}
		newHash := rs.Primary.Attributes["source_hash"]
		if newHash == *oldHashPtr {
			return fmt.Errorf("hash did not change: %s", newHash)
		}
		return nil
	}
}
