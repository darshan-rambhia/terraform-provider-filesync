package acceptance

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccFileResource_BasicWithContainer(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "test content for basic test\n")
	remotePath := "/tmp/test-basic.txt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_file.test", "destination", remotePath),
					resource.TestCheckResourceAttr("filesync_file.test", "host", container.Host),
					resource.TestCheckResourceAttrSet("filesync_file.test", "source_hash"),
					resource.TestCheckResourceAttrSet("filesync_file.test", "size"),
					resource.TestCheckResourceAttr("filesync_file.test", "mode", "0644"),
					CheckRemoteFileExists(container, remotePath),
					CheckRemoteFileContent(container, remotePath, "test content for basic test\n"),
				),
			},
		},
	})
}

func TestAccFileResource_UpdateContent(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile1 := CreateTestSourceFile(t, "initial content\n")
	remotePath := "/tmp/test-update.txt"

	var initialHash string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile1, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_file.test", "destination", remotePath),
					CheckRemoteFileContent(container, remotePath, "initial content\n"),
					CaptureHash("filesync_file.test", &initialHash),
				),
			},
			{
				PreConfig: func() {
					if err := os.WriteFile(sourceFile1, []byte("updated content\n"), 0644); err != nil {
						t.Fatalf("failed to update source file: %v", err)
					}
				},
				Config: cfg.FileResourceConfig("test", sourceFile1, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileContent(container, remotePath, "updated content\n"),
					CheckHashChanged("filesync_file.test", &initialHash),
				),
			},
		},
	})
}

func TestAccFileResource_Permissions(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "permissions test\n")
	remotePath := "/tmp/test-perms.txt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0600"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_file.test", "mode", "0600"),
					CheckRemoteFileMode(container, remotePath, "600"),
				),
			},
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0755"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_file.test", "mode", "0755"),
					CheckRemoteFileMode(container, remotePath, "755"),
				),
			},
		},
	})
}

func TestAccFileResource_NestedDirectory(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "nested dir test\n")
	remotePath := "/tmp/deeply/nested/directory/file.txt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_file.test", "destination", remotePath),
					CheckRemoteFileExists(container, remotePath),
					CheckRemoteFileContent(container, remotePath, "nested dir test\n"),
				),
			},
		},
	})
}

func TestAccFileResource_Delete(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "delete test\n")
	remotePath := "/tmp/test-delete.txt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
				),
			},
			{
				Config: cfg.ProviderOnlyConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileNotExists(container, remotePath),
				),
			},
		},
	})
}

func TestAccFileResource_InlineKey(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "inline key test\n")
	remotePath := "/tmp/test-inline-key.txt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfigWithInlineKey("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
					CheckRemoteFileContent(container, remotePath, "inline key test\n"),
				),
			},
		},
	})
}

func TestAccFileResource_Import(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "import test content\n")
	remotePath := "/tmp/test-import.txt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
				),
			},
			{
				ResourceName: "filesync_file.test",
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					return fmt.Sprintf("%s:%s", container.Host, remotePath), nil
				},
				ImportStateVerify: false,
			},
		},
	})
}

func TestAccFileResource_InvalidImportID(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)
	sourceFile := CreateTestSourceFile(t, "invalid import test\n")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile, "/tmp/test.txt", "0644"),
			},
			{
				ResourceName:  "filesync_file.test",
				ImportState:   true,
				ImportStateId: "invalid-import-id",
				ExpectError:   regexp.MustCompile(`Invalid Import ID`),
			},
		},
	})
}

// TestAccFileResource_DriftDetection tests that external changes to remote files are detected.
// Note: Drift detection only occurs during Update. Since we keep Read/Plan local-only (no remote
// connection), drift is only detected when the local file also changes, triggering an Update.
func TestAccFileResource_DriftDetection(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "original content from terraform\n")
	remotePath := "/tmp/test-drift.txt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the file normally.
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
					CheckRemoteFileContent(container, remotePath, "original content from terraform\n"),
				),
			},
			// Step 2: Externally modify the remote file AND change the local file.
			// The local change triggers Update, which then detects the remote drift.
			{
				PreConfig: func() {
					// Simulate external modification (someone edited the file on the server).
					_, err := container.runCommand(fmt.Sprintf("echo 'modified externally' > %s", remotePath))
					if err != nil {
						t.Fatalf("failed to externally modify file: %v", err)
					}
					// Also modify local file to trigger Update where drift is detected.
					if err := os.WriteFile(sourceFile, []byte("new local content\n"), 0644); err != nil {
						t.Fatalf("failed to modify local file: %v", err)
					}
				},
				Config:      cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				ExpectError: regexp.MustCompile(`Remote file drift detected|Cannot read remote file`),
			},
		},
	})
}

// TestAccFileResource_BinaryFile tests syncing binary content.
func TestAccFileResource_BinaryFile(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	// Create a file with binary content (null bytes, non-printable chars).
	binaryContent := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	sourceFile := CreateTestSourceFileBytes(t, binaryContent)
	remotePath := "/tmp/test-binary.bin"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
					CheckRemoteFileSizeEquals(container, remotePath, int64(len(binaryContent))),
				),
			},
		},
	})
}

// TestAccFileResource_SpecialCharsInPath tests file paths with special characters.
func TestAccFileResource_SpecialCharsInPath(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "special path test\n")

	// Test path with spaces.
	remotePath := "/tmp/test dir/file with spaces.txt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
					CheckRemoteFileContent(container, remotePath, "special path test\n"),
				),
			},
		},
	})
}

// TestAccFileResource_MultipleFilesToSameHost tests syncing multiple files to the same host.
// This is a common pattern and tests connection handling.
func TestAccFileResource_MultipleFilesToSameHost(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile1 := CreateTestSourceFile(t, "content for file 1\n")
	sourceFile2 := CreateTestSourceFile(t, "content for file 2\n")
	sourceFile3 := CreateTestSourceFile(t, "content for file 3\n")

	config := fmt.Sprintf(`%s
resource "filesync_file" "file1" {
  source      = %q
  destination = "/tmp/multi-test-1.txt"
  host        = %q
  mode        = "0644"
%s%s}

resource "filesync_file" "file2" {
  source      = %q
  destination = "/tmp/multi-test-2.txt"
  host        = %q
  mode        = "0644"
%s%s}

resource "filesync_file" "file3" {
  source      = %q
  destination = "/tmp/multi-test-3.txt"
  host        = %q
  mode        = "0755"
%s%s}
`, cfg.ProviderBlock(),
		sourceFile1, cfg.Host, cfg.SSHAttributes(), cfg.OwnerAttributes(),
		sourceFile2, cfg.Host, cfg.SSHAttributes(), cfg.OwnerAttributes(),
		sourceFile3, cfg.Host, cfg.SSHAttributes(), cfg.OwnerAttributes())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, "/tmp/multi-test-1.txt"),
					CheckRemoteFileExists(container, "/tmp/multi-test-2.txt"),
					CheckRemoteFileExists(container, "/tmp/multi-test-3.txt"),
					CheckRemoteFileContent(container, "/tmp/multi-test-1.txt", "content for file 1\n"),
					CheckRemoteFileContent(container, "/tmp/multi-test-2.txt", "content for file 2\n"),
					CheckRemoteFileContent(container, "/tmp/multi-test-3.txt", "content for file 3\n"),
					CheckRemoteFileMode(container, "/tmp/multi-test-3.txt", "755"),
				),
			},
		},
	})
}

// TestAccFileResource_NoOpWhenUnchanged tests that apply is a no-op when file hasn't changed.
func TestAccFileResource_NoOpWhenUnchanged(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "unchanged content\n")
	remotePath := "/tmp/test-noop.txt"

	var initialHash string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the file.
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
					CaptureHash("filesync_file.test", &initialHash),
				),
			},
			// Step 2: Apply again with no changes - should be a no-op.
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Hash should be the same.
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["filesync_file.test"]
						if !ok {
							return fmt.Errorf("resource not found")
						}
						currentHash := rs.Primary.Attributes["source_hash"]
						if currentHash != initialHash {
							return fmt.Errorf("hash changed unexpectedly: %s -> %s", initialHash, currentHash)
						}
						return nil
					},
				),
			},
		},
	})
}

// TestAccFileResource_LargeFile tests syncing larger files (1MB).
func TestAccFileResource_LargeFile(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	// Create a 1MB file.
	size := 1024 * 1024 // 1MB
	largeContent := make([]byte, size)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	sourceFile := CreateTestSourceFileBytes(t, largeContent)
	remotePath := "/tmp/test-large.bin"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
					CheckRemoteFileSizeEquals(container, remotePath, int64(size)),
					resource.TestCheckResourceAttr("filesync_file.test", "size", fmt.Sprintf("%d", size)),
				),
			},
		},
	})
}

// TestAccFileResource_HiddenFile tests syncing files starting with a dot.
func TestAccFileResource_HiddenFile(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "hidden file content\n")
	remotePath := "/tmp/.hidden-config"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0600"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
					CheckRemoteFileContent(container, remotePath, "hidden file content\n"),
					CheckRemoteFileMode(container, remotePath, "600"),
				),
			},
		},
	})
}

// TestAccFileResource_ConnectionPooling tests that connection pooling works correctly.
// Multiple files are synced using the same pooled connection.
func TestAccFileResource_ConnectionPooling(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	// Create multiple source files.
	sourceFile1 := CreateTestSourceFile(t, "pooled content 1\n")
	sourceFile2 := CreateTestSourceFile(t, "pooled content 2\n")
	sourceFile3 := CreateTestSourceFile(t, "pooled content 3\n")

	remotePath1 := "/tmp/pooled-file1.txt"
	remotePath2 := "/tmp/pooled-file2.txt"
	remotePath3 := "/tmp/pooled-file3.txt"

	// Generate config with pooling enabled and multiple resources.
	files := []struct{ Name, Source, Destination, Mode string }{
		{"file1", sourceFile1, remotePath1, "0644"},
		{"file2", sourceFile2, remotePath2, "0644"},
		{"file3", sourceFile3, remotePath3, "0644"},
	}
	config := cfg.MultipleFileResourcesWithPooling(files)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify all files were synced correctly.
					CheckRemoteFileExists(container, remotePath1),
					CheckRemoteFileExists(container, remotePath2),
					CheckRemoteFileExists(container, remotePath3),
					CheckRemoteFileContent(container, remotePath1, "pooled content 1\n"),
					CheckRemoteFileContent(container, remotePath2, "pooled content 2\n"),
					CheckRemoteFileContent(container, remotePath3, "pooled content 3\n"),
				),
			},
		},
	})
}

// TestAccFileResource_ConnectionPoolingUpdate tests connection pooling during updates.
func TestAccFileResource_ConnectionPoolingUpdate(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "initial pooled content\n")
	remotePath := "/tmp/pooled-update.txt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Initial creation with pooling.
				Config: cfg.FileResourceConfigWithPooling("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
					CheckRemoteFileContent(container, remotePath, "initial pooled content\n"),
				),
			},
			{
				// Update content (connection should be reused).
				PreConfig: func() {
					if err := os.WriteFile(sourceFile, []byte("updated pooled content\n"), 0644); err != nil {
						t.Fatalf("Failed to update source file: %v", err)
					}
				},
				Config: cfg.FileResourceConfigWithPooling("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileContent(container, remotePath, "updated pooled content\n"),
				),
			},
		},
	})
}

// TestAccFileResource_LocalFileChangeDetection is a regression test for the bug where
// modifying the local source file didn't trigger an update because Read was incorrectly
// updating source_hash in state. This test explicitly verifies that:
// 1. The plan modifier correctly computes the new hash during planning
// 2. An update is triggered and the remote file is actually updated.
func TestAccFileResource_LocalFileChangeDetection(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceFile := CreateTestSourceFile(t, "version 1 content\n")
	remotePath := "/tmp/test-local-change-detection.txt"

	var initialHash string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the file.
			{
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath),
					CheckRemoteFileContent(container, remotePath, "version 1 content\n"),
					CaptureHash("filesync_file.test", &initialHash),
				),
			},
			// Step 2: Modify LOCAL file only (no config change).
			// This is the key regression test - the plan modifier must detect this change.
			{
				PreConfig: func() {
					// Modify the local source file.
					if err := os.WriteFile(sourceFile, []byte("version 2 content\n"), 0644); err != nil {
						t.Fatalf("failed to update source file: %v", err)
					}
				},
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// CRITICAL: Verify the remote file was ACTUALLY updated.
					// This would fail with the bug because Update was never called.
					CheckRemoteFileContent(container, remotePath, "version 2 content\n"),
					// Verify the hash changed in state.
					CheckHashChanged("filesync_file.test", &initialHash),
				),
			},
			// Step 3: Modify again to ensure it's not a one-time fluke.
			{
				PreConfig: func() {
					if err := os.WriteFile(sourceFile, []byte("version 3 content\n"), 0644); err != nil {
						t.Fatalf("failed to update source file: %v", err)
					}
				},
				Config: cfg.FileResourceConfig("test", sourceFile, remotePath, "0644"),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileContent(container, remotePath, "version 3 content\n"),
				),
			},
		},
	})
}
