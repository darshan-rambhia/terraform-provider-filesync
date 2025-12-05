package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// TestExpandPath tests the expandPath helper function.
func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("could not get home dir: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "absolute path unchanged",
			input:    "/etc/nginx/nginx.conf",
			expected: "/etc/nginx/nginx.conf",
		},
		{
			name:     "relative path unchanged",
			input:    "config/app.conf",
			expected: "config/app.conf",
		},
		{
			name:     "tilde expands to home",
			input:    "~/.ssh/id_rsa",
			expected: filepath.Join(home, ".ssh/id_rsa"),
		},
		{
			name:     "tilde only",
			input:    "~",
			expected: home,
		},
		{
			name:     "tilde with slash",
			input:    "~/",
			expected: filepath.Join(home, ""),
		},
		{
			name:     "empty path",
			input:    "",
			expected: "",
		},
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

// TestHashFile tests the hashFile helper function.
func TestHashFile(t *testing.T) {
	// Create a temp file with known content.
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("Hello, World!")

	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Calculate expected hash.
	h := sha256.New()
	h.Write(content)
	expectedHash := "sha256:" + hex.EncodeToString(h.Sum(nil))

	// Test hashFile.
	hash, size, err := hashFile(testFile)
	if err != nil {
		t.Fatalf("hashFile() error: %v", err)
	}

	if hash != expectedHash {
		t.Errorf("hashFile() hash = %q, want %q", hash, expectedHash)
	}

	if size != int64(len(content)) {
		t.Errorf("hashFile() size = %d, want %d", size, len(content))
	}
}

// TestHashFile_Empty tests hashFile with empty file.
func TestHashFile_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")

	if err := os.WriteFile(testFile, []byte{}, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	hash, size, err := hashFile(testFile)
	if err != nil {
		t.Fatalf("hashFile() error: %v", err)
	}

	if size != 0 {
		t.Errorf("hashFile() size = %d, want 0", size)
	}

	// Empty file should have a valid hash.
	if len(hash) != 71 { // "sha256:" + 64 hex chars
		t.Errorf("hashFile() hash length = %d, want 71", len(hash))
	}
}

// TestHashFile_NotFound tests hashFile with non-existent file.
func TestHashFile_NotFound(t *testing.T) {
	_, _, err := hashFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("hashFile() expected error for non-existent file")
	}
}

// TestHashFile_LargeFile tests hashFile with larger content.
func TestHashFile_LargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "large.txt")

	// Create a 1MB file.
	content := make([]byte, 1024*1024)
	for i := range content {
		content[i] = byte(i % 256)
	}

	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	hash, size, err := hashFile(testFile)
	if err != nil {
		t.Fatalf("hashFile() error: %v", err)
	}

	if size != int64(len(content)) {
		t.Errorf("hashFile() size = %d, want %d", size, len(content))
	}

	if hash[:7] != "sha256:" {
		t.Errorf("hashFile() hash prefix = %q, want 'sha256:'", hash[:7])
	}
}

// TestScanDirectory tests the scanDirectory function.
func TestScanDirectory(t *testing.T) {
	// Create a temp directory structure.
	tmpDir := t.TempDir()

	// Create files.
	files := map[string]string{
		"file1.txt":        "content1",
		"file2.txt":        "content2",
		"subdir/file3.txt": "content3",
	}

	for path, content := range files {
		fullPath := filepath.Join(tmpDir, path)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}
	}

	// Scan without excludes.
	result, err := scanDirectory(tmpDir, nil)
	if err != nil {
		t.Fatalf("scanDirectory() error: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("scanDirectory() found %d files, want 3", len(result))
	}

	// Check that files are sorted.
	for i := 1; i < len(result); i++ {
		if result[i-1].RelPath > result[i].RelPath {
			t.Error("scanDirectory() files not sorted")
		}
	}
}

// TestScanDirectory_WithExcludes tests scanDirectory with exclude patterns.
func TestScanDirectory_WithExcludes(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files including some to exclude.
	files := map[string]string{
		"file.txt":     "keep",
		"file.tmp":     "exclude",
		"backup.bak":   "exclude",
		".git/config":  "exclude",
		"src/main.go":  "keep",
		"src/test.tmp": "exclude",
	}

	for path, content := range files {
		fullPath := filepath.Join(tmpDir, path)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}
	}

	excludes := []string{"*.tmp", "*.bak", ".git"}
	result, err := scanDirectory(tmpDir, excludes)
	if err != nil {
		t.Fatalf("scanDirectory() error: %v", err)
	}

	// Should only have file.txt and src/main.go
	if len(result) != 2 {
		t.Errorf("scanDirectory() with excludes found %d files, want 2", len(result))
	}

	// Verify excluded files are not present.
	for _, f := range result {
		if f.RelPath == "file.tmp" || f.RelPath == "backup.bak" ||
			strings.HasPrefix(f.RelPath, ".git") || f.RelPath == "src/test.tmp" {
			t.Errorf("scanDirectory() should have excluded %s", f.RelPath)
		}
	}
}

// TestScanDirectory_Empty tests scanDirectory with empty directory.
func TestScanDirectory_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	result, err := scanDirectory(tmpDir, nil)
	if err != nil {
		t.Fatalf("scanDirectory() error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("scanDirectory() found %d files, want 0", len(result))
	}
}

// TestScanDirectory_NotFound tests scanDirectory with non-existent directory.
func TestScanDirectory_NotFound(t *testing.T) {
	_, err := scanDirectory("/nonexistent/directory", nil)
	if err == nil {
		t.Error("scanDirectory() expected error for non-existent directory")
	}
}

// TestShouldExclude tests the shouldExclude function.
func TestShouldExclude(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		expected bool
	}{
		{
			name:     "no patterns",
			path:     "file.txt",
			patterns: nil,
			expected: false,
		},
		{
			name:     "matching extension",
			path:     "file.tmp",
			patterns: []string{"*.tmp"},
			expected: true,
		},
		{
			name:     "non-matching extension",
			path:     "file.txt",
			patterns: []string{"*.tmp"},
			expected: false,
		},
		{
			name:     "matching directory",
			path:     ".git/config",
			patterns: []string{".git"},
			expected: true,
		},
		{
			name:     "multiple patterns - first matches",
			path:     "file.tmp",
			patterns: []string{"*.tmp", "*.bak", ".git"},
			expected: true,
		},
		{
			name:     "multiple patterns - last matches",
			path:     ".git/objects/abc",
			patterns: []string{"*.tmp", "*.bak", ".git"},
			expected: true,
		},
		{
			name:     "multiple patterns - none match",
			path:     "src/main.go",
			patterns: []string{"*.tmp", "*.bak", ".git"},
			expected: false,
		},
		{
			name:     "nested path with matching component",
			path:     "src/.git/config",
			patterns: []string{".git"},
			expected: true,
		},
		{
			name:     "exact filename match",
			path:     "Dockerfile",
			patterns: []string{"Dockerfile"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldExclude(tt.path, tt.patterns)
			if result != tt.expected {
				t.Errorf("shouldExclude(%q, %v) = %v, want %v",
					tt.path, tt.patterns, result, tt.expected)
			}
		})
	}
}

// TestComputeCombinedHash tests the computeCombinedHash function.
func TestComputeCombinedHash(t *testing.T) {
	files := []FileInfo{
		{RelPath: "a.txt", Hash: "sha256:abc", Size: 10},
		{RelPath: "b.txt", Hash: "sha256:def", Size: 20},
	}

	hash1 := computeCombinedHash(files)

	// Hash should have correct prefix.
	if hash1[:7] != "sha256:" {
		t.Errorf("computeCombinedHash() prefix = %q, want 'sha256:'", hash1[:7])
	}

	// Hash should have correct length.
	if len(hash1) != 71 {
		t.Errorf("computeCombinedHash() length = %d, want 71", len(hash1))
	}

	// Same input should produce same hash.
	hash2 := computeCombinedHash(files)
	if hash1 != hash2 {
		t.Error("computeCombinedHash() should be deterministic")
	}

	// Different input should produce different hash.
	files2 := []FileInfo{
		{RelPath: "a.txt", Hash: "sha256:abc", Size: 10},
		{RelPath: "c.txt", Hash: "sha256:xyz", Size: 30},
	}
	hash3 := computeCombinedHash(files2)
	if hash1 == hash3 {
		t.Error("computeCombinedHash() should produce different hash for different input")
	}
}

// TestComputeCombinedHash_Empty tests computeCombinedHash with empty input.
func TestComputeCombinedHash_Empty(t *testing.T) {
	hash := computeCombinedHash(nil)

	if hash[:7] != "sha256:" {
		t.Errorf("computeCombinedHash(nil) prefix = %q, want 'sha256:'", hash[:7])
	}

	// Empty should produce consistent hash.
	hash2 := computeCombinedHash([]FileInfo{})
	if hash != hash2 {
		t.Error("computeCombinedHash() should produce same hash for nil and empty slice")
	}
}

// TestNewFileResource tests NewFileResource constructor.
func TestNewFileResource(t *testing.T) {
	r := NewFileResource()
	if r == nil {
		t.Error("NewFileResource() returned nil")
	}

	// Verify concrete type.
	if _, ok := r.(*FileResource); !ok {
		t.Error("NewFileResource() does not return *FileResource")
	}
}

// TestNewDirectoryResource tests NewDirectoryResource constructor.
func TestNewDirectoryResource(t *testing.T) {
	r := NewDirectoryResource()
	if r == nil {
		t.Error("NewDirectoryResource() returned nil")
	}

	// Verify concrete type.
	if _, ok := r.(*DirectoryResource); !ok {
		t.Error("NewDirectoryResource() does not return *DirectoryResource")
	}
}

// TestFilesyncProvider_New tests the New function.
func TestFilesyncProvider_New(t *testing.T) {
	versions := []string{"1.0.0", "dev", "0.0.1-alpha"}

	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			factory := New(version)
			if factory == nil {
				t.Fatal("New() returned nil factory")
			}

			p := factory()
			if p == nil {
				t.Fatal("factory() returned nil provider")
			}

			// Check it's the expected concrete type.
			if _, ok := p.(*FilesyncProvider); !ok {
				t.Error("provider is not *FilesyncProvider")
			}
		})
	}
}

// TestFilesyncProvider_Metadata tests provider Metadata.
func TestFilesyncProvider_Metadata(t *testing.T) {
	p := New("1.0.0")()

	var resp provider.MetadataResponse
	p.Metadata(context.Background(), provider.MetadataRequest{}, &resp)

	if resp.TypeName != "filesync" {
		t.Errorf("Metadata().TypeName = %q, want 'filesync'", resp.TypeName)
	}

	if resp.Version != "1.0.0" {
		t.Errorf("Metadata().Version = %q, want '1.0.0'", resp.Version)
	}
}

// TestFilesyncProvider_Schema tests provider Schema.
func TestFilesyncProvider_Schema(t *testing.T) {
	p := New("1.0.0")()

	var resp provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema() has errors: %v", resp.Diagnostics)
	}

	// Check that required attributes exist.
	requiredAttrs := []string{
		"ssh_user", "ssh_private_key", "ssh_key_path", "ssh_port",
		"ssh_password", "ssh_certificate", "ssh_certificate_path",
		"bastion_host", "bastion_port", "bastion_user",
		"bastion_private_key", "bastion_key_path", "bastion_password",
	}

	for _, attr := range requiredAttrs {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("Schema() missing attribute %q", attr)
		}
	}
}

// TestFilesyncProvider_Resources tests provider Resources.
func TestFilesyncProvider_Resources(t *testing.T) {
	p := New("1.0.0")().(*FilesyncProvider)

	resources := p.Resources(context.Background())

	if len(resources) != 2 {
		t.Errorf("Resources() returned %d resources, want 2", len(resources))
	}

	// Verify each factory returns a valid resource.
	for i, factory := range resources {
		r := factory()
		if r == nil {
			t.Errorf("Resource factory %d returned nil", i)
		}
	}
}

// TestFilesyncProvider_DataSources tests provider DataSources.
func TestFilesyncProvider_DataSources(t *testing.T) {
	p := New("1.0.0")().(*FilesyncProvider)

	dataSources := p.DataSources(context.Background())

	if len(dataSources) != 1 {
		t.Errorf("DataSources() returned %d data sources, want 1", len(dataSources))
	}

	// Verify factory returns a valid data source.
	ds := dataSources[0]()
	if ds == nil {
		t.Error("DataSource factory returned nil")
	}
}

// TestFileResource_Metadata tests FileResource Metadata.
func TestFileResource_Metadata(t *testing.T) {
	r := NewFileResource().(*FileResource)

	var resp resource.MetadataResponse
	r.Metadata(context.Background(), resource.MetadataRequest{
		ProviderTypeName: "filesync",
	}, &resp)

	if resp.TypeName != "filesync_file" {
		t.Errorf("Metadata().TypeName = %q, want 'filesync_file'", resp.TypeName)
	}
}

// TestDirectoryResource_Metadata tests DirectoryResource Metadata.
func TestDirectoryResource_Metadata(t *testing.T) {
	r := NewDirectoryResource().(*DirectoryResource)

	var resp resource.MetadataResponse
	r.Metadata(context.Background(), resource.MetadataRequest{
		ProviderTypeName: "filesync",
	}, &resp)

	if resp.TypeName != "filesync_directory" {
		t.Errorf("Metadata().TypeName = %q, want 'filesync_directory'", resp.TypeName)
	}
}

// TestFileResource_Schema tests FileResource Schema.
func TestFileResource_Schema(t *testing.T) {
	r := NewFileResource().(*FileResource)

	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema() has errors: %v", resp.Diagnostics)
	}

	// Check required attributes.
	requiredAttrs := []string{"source", "destination", "host"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("Schema() missing attribute %q", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("Schema() attribute %q should be required", attr)
		}
	}

	// Check computed attributes.
	computedAttrs := []string{"id", "source_hash", "size"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("Schema() missing attribute %q", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("Schema() attribute %q should be computed", attr)
		}
	}
}

// TestDirectoryResource_Schema tests DirectoryResource Schema.
func TestDirectoryResource_Schema(t *testing.T) {
	r := NewDirectoryResource().(*DirectoryResource)

	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema() has errors: %v", resp.Diagnostics)
	}

	// Check required attributes.
	requiredAttrs := []string{"source", "destination", "host"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("Schema() missing attribute %q", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("Schema() attribute %q should be required", attr)
		}
	}

	// Check computed attributes.
	computedAttrs := []string{"id", "source_hash", "file_count", "total_size", "file_hashes"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("Schema() missing attribute %q", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("Schema() attribute %q should be computed", attr)
		}
	}
}

// TestNewHostDataSource tests NewHostDataSource constructor.
func TestNewHostDataSource(t *testing.T) {
	ds := NewHostDataSource()
	if ds == nil {
		t.Error("NewHostDataSource() returned nil")
	}

	// Verify concrete type.
	if _, ok := ds.(*HostDataSource); !ok {
		t.Error("NewHostDataSource() does not return *HostDataSource")
	}
}

// TestHostDataSource_Metadata tests HostDataSource Metadata.
func TestHostDataSource_Metadata(t *testing.T) {
	ds := NewHostDataSource().(*HostDataSource)

	var resp datasource.MetadataResponse
	ds.Metadata(context.Background(), datasource.MetadataRequest{
		ProviderTypeName: "filesync",
	}, &resp)

	if resp.TypeName != "filesync_host" {
		t.Errorf("Metadata().TypeName = %q, want 'filesync_host'", resp.TypeName)
	}
}

// TestHostDataSource_Schema tests HostDataSource Schema.
func TestHostDataSource_Schema(t *testing.T) {
	ds := NewHostDataSource().(*HostDataSource)

	var resp datasource.SchemaResponse
	ds.Schema(context.Background(), datasource.SchemaRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema() has errors: %v", resp.Diagnostics)
	}

	// Check required attributes.
	a, ok := resp.Schema.Attributes["address"]
	if !ok {
		t.Error("Schema() missing 'address' attribute")
	} else if !a.IsRequired() {
		t.Error("Schema() 'address' should be required")
	}

	// Check optional attributes.
	optionalAttrs := []string{
		"ssh_user", "ssh_private_key", "ssh_key_path", "ssh_port",
		"ssh_password", "ssh_certificate", "ssh_certificate_path",
	}
	for _, attr := range optionalAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("Schema() missing attribute %q", attr)
			continue
		}
		if !a.IsOptional() {
			t.Errorf("Schema() attribute %q should be optional", attr)
		}
	}

	// Check computed attributes.
	a, ok = resp.Schema.Attributes["id"]
	if !ok {
		t.Error("Schema() missing 'id' attribute")
	} else if !a.IsComputed() {
		t.Error("Schema() 'id' should be computed")
	}
}

// TestFilesyncProvider_Configure_Success tests successful provider configuration.
func TestFilesyncProvider_Configure_Success(t *testing.T) {
	p := New("1.0.0")().(*FilesyncProvider)

	var schemaResp provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &schemaResp)

	// Build config value with provider settings.
	configVal := buildProviderConfigValue(t, schemaResp, FilesyncProviderModel{
		SSHUser:    types.StringValue("deploy"),
		SSHKeyPath: types.StringValue("~/.ssh/id_rsa"),
		SSHPort:    types.Int64Value(22),
	})

	config := tfsdk.Config{
		Schema: schemaResp.Schema,
		Raw:    configVal,
	}

	var resp provider.ConfigureResponse
	p.Configure(context.Background(), provider.ConfigureRequest{
		Config: config,
	}, &resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Configure() unexpected error: %v", resp.Diagnostics)
	}

	// Verify data was passed through.
	if resp.DataSourceData == nil {
		t.Error("Configure() did not set DataSourceData")
	}
	if resp.ResourceData == nil {
		t.Error("Configure() did not set ResourceData")
	}
}

// TestFilesyncProvider_Configure_WithBastion tests configuration with bastion settings.
func TestFilesyncProvider_Configure_WithBastion(t *testing.T) {
	p := New("1.0.0")().(*FilesyncProvider)

	var schemaResp provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &schemaResp)

	configVal := buildProviderConfigValue(t, schemaResp, FilesyncProviderModel{
		SSHUser:     types.StringValue("deploy"),
		SSHKeyPath:  types.StringValue("~/.ssh/id_rsa"),
		SSHPort:     types.Int64Value(22),
		BastionHost: types.StringValue("bastion.example.com"),
		BastionPort: types.Int64Value(22),
		BastionUser: types.StringValue("jumpuser"),
	})

	config := tfsdk.Config{
		Schema: schemaResp.Schema,
		Raw:    configVal,
	}

	var resp provider.ConfigureResponse
	p.Configure(context.Background(), provider.ConfigureRequest{
		Config: config,
	}, &resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Configure() unexpected error: %v", resp.Diagnostics)
	}

	// Verify the config was captured.
	providerConfig, ok := resp.ResourceData.(*FilesyncProviderModel)
	if !ok {
		t.Fatal("ResourceData is not *FilesyncProviderModel")
	}

	if providerConfig.BastionHost.ValueString() != "bastion.example.com" {
		t.Errorf("BastionHost = %q, want %q", providerConfig.BastionHost.ValueString(), "bastion.example.com")
	}
}

// TestFilesyncProvider_Configure_EmptyConfig tests configuration with no settings.
func TestFilesyncProvider_Configure_EmptyConfig(t *testing.T) {
	p := New("1.0.0")().(*FilesyncProvider)

	var schemaResp provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &schemaResp)

	// Empty config - all null values.
	configVal := buildProviderConfigValue(t, schemaResp, FilesyncProviderModel{})

	config := tfsdk.Config{
		Schema: schemaResp.Schema,
		Raw:    configVal,
	}

	var resp provider.ConfigureResponse
	p.Configure(context.Background(), provider.ConfigureRequest{
		Config: config,
	}, &resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Configure() unexpected error: %v", resp.Diagnostics)
	}
}

// Helper to build provider config terraform value.
func buildProviderConfigValue(t *testing.T, schemaResp provider.SchemaResponse, data FilesyncProviderModel) tftypes.Value {
	t.Helper()

	strVal := func(s types.String) interface{} {
		if s.IsNull() || s.IsUnknown() {
			return nil
		}
		return s.ValueString()
	}

	int64Val := func(i types.Int64) interface{} {
		if i.IsNull() || i.IsUnknown() {
			return nil
		}
		return i.ValueInt64()
	}

	boolVal := func(b types.Bool) interface{} {
		if b.IsNull() || b.IsUnknown() {
			return nil
		}
		return b.ValueBool()
	}

	return tftypes.NewValue(
		schemaResp.Schema.Type().TerraformType(context.Background()),
		map[string]tftypes.Value{
			"ssh_user":                tftypes.NewValue(tftypes.String, strVal(data.SSHUser)),
			"ssh_private_key":         tftypes.NewValue(tftypes.String, strVal(data.SSHPrivateKey)),
			"ssh_key_path":            tftypes.NewValue(tftypes.String, strVal(data.SSHKeyPath)),
			"ssh_port":                tftypes.NewValue(tftypes.Number, int64Val(data.SSHPort)),
			"ssh_password":            tftypes.NewValue(tftypes.String, strVal(data.SSHPassword)),
			"ssh_certificate":         tftypes.NewValue(tftypes.String, strVal(data.SSHCertificate)),
			"ssh_certificate_path":    tftypes.NewValue(tftypes.String, strVal(data.SSHCertificatePath)),
			"bastion_host":            tftypes.NewValue(tftypes.String, strVal(data.BastionHost)),
			"bastion_port":            tftypes.NewValue(tftypes.Number, int64Val(data.BastionPort)),
			"bastion_user":            tftypes.NewValue(tftypes.String, strVal(data.BastionUser)),
			"bastion_private_key":     tftypes.NewValue(tftypes.String, strVal(data.BastionKey)),
			"bastion_key_path":        tftypes.NewValue(tftypes.String, strVal(data.BastionKeyPath)),
			"bastion_password":        tftypes.NewValue(tftypes.String, strVal(data.BastionPassword)),
			"connection_pool_enabled": tftypes.NewValue(tftypes.Bool, boolVal(data.ConnectionPoolEnabled)),
		},
	)
}
