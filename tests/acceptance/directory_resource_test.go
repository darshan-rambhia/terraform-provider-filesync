package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccDirectoryResource_Basic(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	files := map[string]string{
		"file1.txt": "content of file1\n",
		"file2.txt": "content of file2\n",
	}
	sourceDir := CreateTestSourceDirectory(t, files)
	remotePath := "/tmp/test-dir-basic"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "destination", remotePath),
					resource.TestCheckResourceAttr("filesync_directory.test", "host", container.Host),
					resource.TestCheckResourceAttrSet("filesync_directory.test", "source_hash"),
					resource.TestCheckResourceAttr("filesync_directory.test", "file_count", "2"),
					resource.TestCheckResourceAttr("filesync_directory.test", "mode", "0644"),
					CheckRemoteFileExists(container, remotePath+"/file1.txt"),
					CheckRemoteFileExists(container, remotePath+"/file2.txt"),
					CheckRemoteFileContent(container, remotePath+"/file1.txt", "content of file1\n"),
					CheckRemoteFileContent(container, remotePath+"/file2.txt", "content of file2\n"),
				),
			},
		},
	})
}

func TestAccDirectoryResource_NestedStructure(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	files := map[string]string{
		"root.txt":               "root file\n",
		"subdir/nested.txt":      "nested file\n",
		"subdir/deep/deeper.txt": "deeply nested\n",
	}
	sourceDir := CreateTestSourceDirectory(t, files)
	remotePath := "/tmp/test-dir-nested"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "file_count", "3"),
					CheckRemoteFileExists(container, remotePath+"/root.txt"),
					CheckRemoteFileExists(container, remotePath+"/subdir/nested.txt"),
					CheckRemoteFileExists(container, remotePath+"/subdir/deep/deeper.txt"),
				),
			},
		},
	})
}

func TestAccDirectoryResource_WithExcludes(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	files := map[string]string{
		"keep.txt":     "keep this\n",
		"exclude.tmp":  "exclude this\n",
		"backup.bak":   "exclude this too\n",
		"subdir/a.txt": "keep nested\n",
		"subdir/b.tmp": "exclude nested\n",
	}
	sourceDir := CreateTestSourceDirectory(t, files)
	remotePath := "/tmp/test-dir-exclude"
	excludes := []string{"*.tmp", "*.bak"}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", excludes),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "file_count", "2"),
					CheckRemoteFileExists(container, remotePath+"/keep.txt"),
					CheckRemoteFileExists(container, remotePath+"/subdir/a.txt"),
					CheckRemoteFileNotExists(container, remotePath+"/exclude.tmp"),
					CheckRemoteFileNotExists(container, remotePath+"/backup.bak"),
					CheckRemoteFileNotExists(container, remotePath+"/subdir/b.tmp"),
				),
			},
		},
	})
}

func TestAccDirectoryResource_UpdateContent(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	initialFiles := map[string]string{
		"file1.txt": "initial content\n",
	}
	sourceDir := CreateTestSourceDirectory(t, initialFiles)
	remotePath := "/tmp/test-dir-update"

	var initialHash string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "file_count", "1"),
					CheckRemoteFileContent(container, remotePath+"/file1.txt", "initial content\n"),
					CaptureHash("filesync_directory.test", &initialHash),
				),
			},
			{
				PreConfig: func() {
					if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("updated content\n"), 0644); err != nil {
						t.Fatalf("failed to update file: %v", err)
					}
					if err := os.WriteFile(filepath.Join(sourceDir, "file2.txt"), []byte("new file\n"), 0644); err != nil {
						t.Fatalf("failed to create file: %v", err)
					}
				},
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "file_count", "2"),
					CheckRemoteFileContent(container, remotePath+"/file1.txt", "updated content\n"),
					CheckRemoteFileContent(container, remotePath+"/file2.txt", "new file\n"),
					CheckHashChanged("filesync_directory.test", &initialHash),
				),
			},
		},
	})
}

func TestAccDirectoryResource_DeleteFiles(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	files := map[string]string{
		"keep.txt":   "keep this\n",
		"remove.txt": "remove this\n",
	}
	sourceDir := CreateTestSourceDirectory(t, files)
	remotePath := "/tmp/test-dir-delete-files"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "file_count", "2"),
					CheckRemoteFileExists(container, remotePath+"/keep.txt"),
					CheckRemoteFileExists(container, remotePath+"/remove.txt"),
				),
			},
			{
				PreConfig: func() {
					if err := os.Remove(filepath.Join(sourceDir, "remove.txt")); err != nil {
						t.Fatalf("failed to remove file: %v", err)
					}
				},
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "file_count", "1"),
					CheckRemoteFileExists(container, remotePath+"/keep.txt"),
					CheckRemoteFileNotExists(container, remotePath+"/remove.txt"),
				),
			},
		},
	})
}

func TestAccDirectoryResource_Permissions(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	files := map[string]string{
		"script.sh": "#!/bin/bash\necho hello\n",
	}
	sourceDir := CreateTestSourceDirectory(t, files)
	remotePath := "/tmp/test-dir-perms"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0755", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "mode", "0755"),
					CheckRemoteFileMode(container, remotePath+"/script.sh", "755"),
				),
			},
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0600", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "mode", "0600"),
					CheckRemoteFileMode(container, remotePath+"/script.sh", "600"),
				),
			},
		},
	})
}

func TestAccDirectoryResource_Delete(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	files := map[string]string{
		"file1.txt":        "content\n",
		"subdir/file2.txt": "nested\n",
	}
	sourceDir := CreateTestSourceDirectory(t, files)
	remotePath := "/tmp/test-dir-destroy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath+"/file1.txt"),
					CheckRemoteFileExists(container, remotePath+"/subdir/file2.txt"),
				),
			},
			{
				Config: cfg.ProviderOnlyConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileNotExists(container, remotePath+"/file1.txt"),
					CheckRemoteFileNotExists(container, remotePath+"/subdir/file2.txt"),
				),
			},
		},
	})
}

func TestAccDirectoryResource_Import(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	files := map[string]string{
		"file.txt": "import test\n",
	}
	sourceDir := CreateTestSourceDirectory(t, files)
	remotePath := "/tmp/test-dir-import"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, remotePath+"/file.txt"),
				),
			},
			{
				ResourceName: "filesync_directory.test",
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					return fmt.Sprintf("%s:%s", container.Host, remotePath), nil
				},
				ImportStateVerify: false,
			},
		},
	})
}

func TestAccDirectoryResource_InvalidImportID(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)
	sourceDir := CreateTestSourceDirectory(t, map[string]string{"f.txt": "x"})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, "/tmp/x", "0644", nil),
			},
			{
				ResourceName:  "filesync_directory.test",
				ImportState:   true,
				ImportStateId: "invalid-import-id",
				ExpectError:   regexp.MustCompile(`Invalid Import ID`),
			},
		},
	})
}

func TestAccDirectoryResource_EmptyDirectory(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	sourceDir := CreateTestSourceDirectory(t, map[string]string{})
	remotePath := "/tmp/test-dir-empty"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "file_count", "0"),
				),
			},
		},
	})
}

func TestAccDirectoryResource_LargeFile(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	// Create a 1MB file.
	largeContent := make([]byte, 1024*1024)
	for i := range largeContent {
		largeContent[i] = byte('A' + (i % 26))
	}

	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "large")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("failed to create source directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "large.txt"), largeContent, 0644); err != nil {
		t.Fatalf("failed to create large file: %v", err)
	}

	remotePath := "/tmp/test-dir-large"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.DirectoryResourceConfig("test", sourceDir, remotePath, "0644", nil),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("filesync_directory.test", "file_count", "1"),
					CheckRemoteFileExists(container, remotePath+"/large.txt"),
				),
			},
		},
	})
}
