package provider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// TestDirectoryResource_CreateSSHClient tests the createSSHClient method.
func TestDirectoryResource_CreateSSHClient(t *testing.T) {
	mock := NewMockSSHClient()
	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := &DirectoryResourceModel{
		Host:    types.StringValue("192.168.1.100"),
		SSHPort: types.Int64Value(22),
		SSHUser: types.StringValue("testuser"),
	}

	client, err := r.createSSHClient(data)
	if err != nil {
		t.Fatalf("createSSHClient() error: %v", err)
	}

	if client == nil {
		t.Error("createSSHClient() returned nil client")
	}
}

// TestDirectoryResource_CreateSSHClientError tests error handling in createSSHClient.
func TestDirectoryResource_CreateSSHClientError(t *testing.T) {
	expectedErr := errors.New("connection failed")
	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactoryWithError(expectedErr),
	}

	data := &DirectoryResourceModel{
		Host:    types.StringValue("192.168.1.100"),
		SSHPort: types.Int64Value(22),
		SSHUser: types.StringValue("testuser"),
	}

	_, err := r.createSSHClient(data)
	if err == nil {
		t.Error("createSSHClient() expected error, got nil")
	}
}

// TestDirectoryResource_CreateSSHClientWithProviderDefaults tests provider config fallback.
func TestDirectoryResource_CreateSSHClientWithProviderDefaults(t *testing.T) {
	mock := NewMockSSHClient()

	providerConfig := &FilesyncProviderModel{
		SSHUser:     types.StringValue("provider-user"),
		SSHKeyPath:  types.StringValue("~/.ssh/id_rsa"),
		SSHPort:     types.Int64Value(2222),
		SSHPassword: types.StringValue("provider-pass"),
	}

	r := &DirectoryResource{
		providerConfig:   providerConfig,
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := &DirectoryResourceModel{
		Host:    types.StringValue("192.168.1.100"),
		SSHPort: types.Int64Value(22),
		SSHUser: types.StringValue("root"),
	}

	client, err := r.createSSHClient(data)
	if err != nil {
		t.Fatalf("createSSHClient() error: %v", err)
	}

	if client == nil {
		t.Error("createSSHClient() returned nil client")
	}
}

// TestDirectoryResource_CreateSSHClientWithBastion tests bastion host configuration.
func TestDirectoryResource_CreateSSHClientWithBastion(t *testing.T) {
	mock := NewMockSSHClient()

	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := &DirectoryResourceModel{
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		BastionHost: types.StringValue("bastion.example.com"),
		BastionPort: types.Int64Value(22),
		BastionUser: types.StringValue("bastion-user"),
	}

	client, err := r.createSSHClient(data)
	if err != nil {
		t.Fatalf("createSSHClient() with bastion error: %v", err)
	}

	if client == nil {
		t.Error("createSSHClient() returned nil client")
	}
}

// TestDirectoryResource_CreateSSHClientWithCertificate tests certificate authentication.
func TestDirectoryResource_CreateSSHClientWithCertificate(t *testing.T) {
	mock := NewMockSSHClient()

	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := &DirectoryResourceModel{
		Host:           types.StringValue("192.168.1.100"),
		SSHPort:        types.Int64Value(22),
		SSHUser:        types.StringValue("root"),
		SSHPrivateKey:  types.StringValue("private-key-content"),
		SSHCertificate: types.StringValue("cert-content"),
	}

	client, err := r.createSSHClient(data)
	if err != nil {
		t.Fatalf("createSSHClient() with certificate error: %v", err)
	}

	if client == nil {
		t.Error("createSSHClient() returned nil client")
	}
}

// TestDirectoryResource_CreateSSHClientWithCertificatePath tests certificate path authentication.
func TestDirectoryResource_CreateSSHClientWithCertificatePath(t *testing.T) {
	mock := NewMockSSHClient()

	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := &DirectoryResourceModel{
		Host:               types.StringValue("192.168.1.100"),
		SSHPort:            types.Int64Value(22),
		SSHUser:            types.StringValue("root"),
		SSHKeyPath:         types.StringValue("~/.ssh/id_rsa"),
		SSHCertificatePath: types.StringValue("~/.ssh/id_rsa-cert.pub"),
	}

	client, err := r.createSSHClient(data)
	if err != nil {
		t.Fatalf("createSSHClient() with certificate path error: %v", err)
	}

	if client == nil {
		t.Error("createSSHClient() returned nil client")
	}
}

// TestDirectoryResource_CreateSSHClientWithProviderCertificate tests provider certificate config.
func TestDirectoryResource_CreateSSHClientWithProviderCertificate(t *testing.T) {
	mock := NewMockSSHClient()

	providerConfig := &FilesyncProviderModel{
		SSHPrivateKey:  types.StringValue("provider-key"),
		SSHCertificate: types.StringValue("provider-cert"),
	}

	r := &DirectoryResource{
		providerConfig:   providerConfig,
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := &DirectoryResourceModel{
		Host:    types.StringValue("192.168.1.100"),
		SSHPort: types.Int64Value(22),
		SSHUser: types.StringValue("root"),
	}

	client, err := r.createSSHClient(data)
	if err != nil {
		t.Fatalf("createSSHClient() with provider certificate error: %v", err)
	}

	if client == nil {
		t.Error("createSSHClient() returned nil client")
	}
}

// TestDirectoryResource_CreateSSHClientWithProviderBastion tests provider bastion config.
func TestDirectoryResource_CreateSSHClientWithProviderBastion(t *testing.T) {
	mock := NewMockSSHClient()

	providerConfig := &FilesyncProviderModel{
		SSHKeyPath:  types.StringValue("~/.ssh/id_rsa"),
		BastionHost: types.StringValue("provider-bastion.example.com"),
		BastionPort: types.Int64Value(22),
		BastionUser: types.StringValue("provider-bastion-user"),
		BastionKey:  types.StringValue("provider-bastion-key"),
	}

	r := &DirectoryResource{
		providerConfig:   providerConfig,
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := &DirectoryResourceModel{
		Host:    types.StringValue("192.168.1.100"),
		SSHPort: types.Int64Value(22),
		SSHUser: types.StringValue("root"),
	}

	client, err := r.createSSHClient(data)
	if err != nil {
		t.Fatalf("createSSHClient() with provider bastion error: %v", err)
	}

	if client == nil {
		t.Error("createSSHClient() returned nil client")
	}
}

// TestDirectoryResource_CreateSSHClientWithAllBastionOptions tests various bastion configurations.
func TestDirectoryResource_CreateSSHClientWithAllBastionOptions(t *testing.T) {
	mock := NewMockSSHClient()

	// Test with bastion key path from provider.
	providerConfig := &FilesyncProviderModel{
		SSHKeyPath:      types.StringValue("~/.ssh/id_rsa"),
		BastionKeyPath:  types.StringValue("~/.ssh/bastion_key"),
		BastionPassword: types.StringValue("bastion-password"),
	}

	r := &DirectoryResource{
		providerConfig:   providerConfig,
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := &DirectoryResourceModel{
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		BastionHost: types.StringValue("bastion.example.com"),
		BastionPort: types.Int64Value(22),
		BastionUser: types.StringValue("bastion-user"),
	}

	client, err := r.createSSHClient(data)
	if err != nil {
		t.Fatalf("createSSHClient() with all bastion options error: %v", err)
	}

	if client == nil {
		t.Error("createSSHClient() returned nil client")
	}
}

// TestDirectoryResource_ImportState_ValidID tests valid import ID parsing.
func TestDirectoryResource_ImportState_ValidID(t *testing.T) {
	tests := []struct {
		name        string
		importID    string
		wantHost    string
		wantDest    string
		shouldError bool
	}{
		{
			name:        "simple host and path",
			importID:    "192.168.1.100:/etc/app",
			wantHost:    "192.168.1.100",
			wantDest:    "/etc/app",
			shouldError: false,
		},
		{
			name:        "hostname with path",
			importID:    "server.example.com:/var/www",
			wantHost:    "server.example.com",
			wantDest:    "/var/www",
			shouldError: false,
		},
		{
			name:        "root directory",
			importID:    "localhost:/configs",
			wantHost:    "localhost",
			wantDest:    "/configs",
			shouldError: false,
		},
		{
			name:        "missing colon",
			importID:    "192.168.1.100/etc/app",
			shouldError: true,
		},
		{
			name:        "no host",
			importID:    ":/etc/app",
			shouldError: true,
		},
		{
			name:        "no destination",
			importID:    "192.168.1.100:",
			shouldError: true,
		},
		{
			name:        "relative path",
			importID:    "192.168.1.100:relative/path",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &DirectoryResource{}

			// Create schema for state.
			var schemaResp resource.SchemaResponse
			r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

			state := tfsdk.State{
				Schema: schemaResp.Schema,
				Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
			}

			resp := &resource.ImportStateResponse{
				State: state,
			}

			r.ImportState(context.Background(), resource.ImportStateRequest{
				ID: tt.importID,
			}, resp)

			if tt.shouldError {
				if !resp.Diagnostics.HasError() {
					t.Error("expected error but got none")
				}
				return
			}

			if resp.Diagnostics.HasError() {
				t.Errorf("unexpected error: %v", resp.Diagnostics)
				return
			}

			// Verify state was set correctly.
			var host, dest types.String
			resp.State.GetAttribute(context.Background(), path.Root("host"), &host)
			resp.State.GetAttribute(context.Background(), path.Root("destination"), &dest)

			if host.ValueString() != tt.wantHost {
				t.Errorf("host = %q, want %q", host.ValueString(), tt.wantHost)
			}
			if dest.ValueString() != tt.wantDest {
				t.Errorf("destination = %q, want %q", dest.ValueString(), tt.wantDest)
			}
		})
	}
}

// TestDirectoryResource_Configure tests the Configure method.
func TestDirectoryResource_Configure(t *testing.T) {
	r := &DirectoryResource{}

	// Test nil provider data.
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{
		ProviderData: nil,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Configure() with nil data should not error: %v", resp.Diagnostics)
	}

	// Test with valid provider data.
	providerConfig := &FilesyncProviderModel{
		SSHUser: types.StringValue("testuser"),
	}

	resp = &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{
		ProviderData: providerConfig,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Configure() with valid data should not error: %v", resp.Diagnostics)
	}

	if r.providerConfig != providerConfig {
		t.Error("Configure() did not set providerConfig")
	}
}

// TestDirectoryResource_ConfigureWrongType tests Configure with wrong type.
func TestDirectoryResource_ConfigureWrongType(t *testing.T) {
	r := &DirectoryResource{}

	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{
		ProviderData: "wrong type",
	}, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Configure() with wrong type should error")
	}
}

// TestDirectoryResource_GetExcludePatterns tests the getExcludePatterns method.
func TestDirectoryResource_GetExcludePatterns(t *testing.T) {
	r := &DirectoryResource{}
	ctx := context.Background()

	// Create a list with actual patterns.
	patternList, diags := types.ListValueFrom(ctx, types.StringType, []string{"*.tmp", "*.bak", ".git"})
	if diags.HasError() {
		t.Fatalf("failed to create list: %v", diags)
	}

	tests := []struct {
		name     string
		exclude  types.List
		expected []string
	}{
		{
			name:     "null list",
			exclude:  types.ListNull(types.StringType),
			expected: nil,
		},
		{
			name:     "unknown list",
			exclude:  types.ListUnknown(types.StringType),
			expected: nil,
		},
		{
			name:     "with patterns",
			exclude:  patternList,
			expected: []string{"*.tmp", "*.bak", ".git"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &DirectoryResourceModel{
				Exclude: tt.exclude,
			}
			var diags resource.CreateResponse
			patterns := r.getExcludePatterns(ctx, data, &diags.Diagnostics)

			if tt.expected == nil && patterns != nil {
				t.Errorf("expected nil, got %v", patterns)
			}
			if tt.expected != nil {
				if len(patterns) != len(tt.expected) {
					t.Errorf("expected %d patterns, got %d", len(tt.expected), len(patterns))
				}
				for i, p := range patterns {
					if p != tt.expected[i] {
						t.Errorf("pattern %d: expected %q, got %q", i, tt.expected[i], p)
					}
				}
			}
		})
	}
}

// Helper function to build DirectoryResourceModel terraform value.
func buildDirectoryTerraformValue(t *testing.T, s schema.Schema, data DirectoryResourceModel) tftypes.Value {
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

	// Build file_hashes map value.
	var fileHashesVal interface{} = nil
	if !data.FileHashes.IsNull() && !data.FileHashes.IsUnknown() {
		hashMap := make(map[string]tftypes.Value)
		elements := data.FileHashes.Elements()
		for k, v := range elements {
			if sv, ok := v.(types.String); ok {
				hashMap[k] = tftypes.NewValue(tftypes.String, sv.ValueString())
			}
		}
		fileHashesVal = hashMap
	}

	// Build exclude list value.
	var excludeVal interface{} = nil
	if !data.Exclude.IsNull() && !data.Exclude.IsUnknown() {
		var excludeList []tftypes.Value
		elements := data.Exclude.Elements()
		for _, v := range elements {
			if sv, ok := v.(types.String); ok {
				excludeList = append(excludeList, tftypes.NewValue(tftypes.String, sv.ValueString()))
			}
		}
		excludeVal = excludeList
	}

	return tftypes.NewValue(
		s.Type().TerraformType(context.Background()),
		map[string]tftypes.Value{
			"source":                   tftypes.NewValue(tftypes.String, strVal(data.Source)),
			"destination":              tftypes.NewValue(tftypes.String, strVal(data.Destination)),
			"host":                     tftypes.NewValue(tftypes.String, strVal(data.Host)),
			"ssh_user":                 tftypes.NewValue(tftypes.String, strVal(data.SSHUser)),
			"ssh_private_key":          tftypes.NewValue(tftypes.String, strVal(data.SSHPrivateKey)),
			"ssh_key_path":             tftypes.NewValue(tftypes.String, strVal(data.SSHKeyPath)),
			"ssh_port":                 tftypes.NewValue(tftypes.Number, int64Val(data.SSHPort)),
			"ssh_password":             tftypes.NewValue(tftypes.String, strVal(data.SSHPassword)),
			"ssh_certificate":          tftypes.NewValue(tftypes.String, strVal(data.SSHCertificate)),
			"ssh_certificate_path":     tftypes.NewValue(tftypes.String, strVal(data.SSHCertificatePath)),
			"bastion_host":             tftypes.NewValue(tftypes.String, strVal(data.BastionHost)),
			"bastion_port":             tftypes.NewValue(tftypes.Number, int64Val(data.BastionPort)),
			"bastion_user":             tftypes.NewValue(tftypes.String, strVal(data.BastionUser)),
			"bastion_private_key":      tftypes.NewValue(tftypes.String, strVal(data.BastionKey)),
			"bastion_key_path":         tftypes.NewValue(tftypes.String, strVal(data.BastionKeyPath)),
			"bastion_password":         tftypes.NewValue(tftypes.String, strVal(data.BastionPassword)),
			"insecure_ignore_host_key": tftypes.NewValue(tftypes.Bool, boolVal(data.InsecureIgnoreHostKey)),
			"known_hosts_file":         tftypes.NewValue(tftypes.String, strVal(data.KnownHostsFile)),
			"strict_host_key_checking": tftypes.NewValue(tftypes.String, strVal(data.StrictHostKeyChecking)),
			"owner":                    tftypes.NewValue(tftypes.String, strVal(data.Owner)),
			"group":                    tftypes.NewValue(tftypes.String, strVal(data.Group)),
			"mode":                     tftypes.NewValue(tftypes.String, strVal(data.Mode)),
			"exclude":                  tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, excludeVal),
			"parallel_uploads":         tftypes.NewValue(tftypes.Number, int64Val(data.ParallelUploads)),
			"symlink_policy":           tftypes.NewValue(tftypes.String, strVal(data.SymlinkPolicy)),
			"id":                       tftypes.NewValue(tftypes.String, strVal(data.ID)),
			"source_hash":              tftypes.NewValue(tftypes.String, strVal(data.SourceHash)),
			"file_count":               tftypes.NewValue(tftypes.Number, int64Val(data.FileCount)),
			"total_size":               tftypes.NewValue(tftypes.Number, int64Val(data.TotalSize)),
			"file_hashes":              tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, fileHashesVal),
		},
	)
}

// TestDirectoryResource_Create_Success tests successful directory creation.
func TestDirectoryResource_Create_Success(t *testing.T) {
	// Create a temp directory with test files.
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("failed to create source dir: %v", err)
	}

	// Create test files.
	if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := NewMockSSHClient()
	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	// Get schema.
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	data := DirectoryResourceModel{
		Source:          types.StringValue(sourceDir),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	plan := tfsdk.Plan{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, data),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
	}

	resp := &resource.CreateResponse{
		State: state,
	}

	r.Create(context.Background(), resource.CreateRequest{
		Plan: plan,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Create() unexpected error: %v", resp.Diagnostics)
	}

	// Verify mock was called.
	if mock.UploadCalls < 2 {
		t.Errorf("expected at least 2 upload calls, got %d", mock.UploadCalls)
	}
	if mock.SetAttributeCalls < 2 {
		t.Errorf("expected at least 2 set attribute calls, got %d", mock.SetAttributeCalls)
	}
}

// TestDirectoryResource_Create_SourceNotFound tests create with non-existent source.
func TestDirectoryResource_Create_SourceNotFound(t *testing.T) {
	mock := NewMockSSHClient()
	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	data := DirectoryResourceModel{
		Source:          types.StringValue("/nonexistent/source"),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	plan := tfsdk.Plan{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, data),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
	}

	resp := &resource.CreateResponse{
		State: state,
	}

	r.Create(context.Background(), resource.CreateRequest{
		Plan: plan,
	}, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Create() expected error for non-existent source, got none")
	}
}

// TestDirectoryResource_Create_SSHConnectionError tests create with SSH connection failure.
func TestDirectoryResource_Create_SSHConnectionError(t *testing.T) {
	// Create a temp directory with test files.
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("failed to create source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactoryWithError(errors.New("connection refused")),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	data := DirectoryResourceModel{
		Source:          types.StringValue(sourceDir),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	plan := tfsdk.Plan{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, data),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
	}

	resp := &resource.CreateResponse{
		State: state,
	}

	r.Create(context.Background(), resource.CreateRequest{
		Plan: plan,
	}, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Create() expected error for SSH connection failure, got none")
	}
}

// TestDirectoryResource_Create_UploadError tests create with upload failure.
func TestDirectoryResource_Create_UploadError(t *testing.T) {
	// Create a temp directory with test files.
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("failed to create source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := NewMockSSHClient()
	mock.UploadError = errors.New("upload failed")
	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	data := DirectoryResourceModel{
		Source:          types.StringValue(sourceDir),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	plan := tfsdk.Plan{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, data),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
	}

	resp := &resource.CreateResponse{
		State: state,
	}

	r.Create(context.Background(), resource.CreateRequest{
		Plan: plan,
	}, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Create() expected error for upload failure, got none")
	}
}

// TestDirectoryResource_Create_SetAttributesError tests create with attribute setting failure.
func TestDirectoryResource_Create_SetAttributesError(t *testing.T) {
	// Create a temp directory with test files.
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("failed to create source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := NewMockSSHClient()
	mock.SetAttributeError = errors.New("permission denied")
	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	data := DirectoryResourceModel{
		Source:          types.StringValue(sourceDir),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	plan := tfsdk.Plan{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, data),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
	}

	resp := &resource.CreateResponse{
		State: state,
	}

	r.Create(context.Background(), resource.CreateRequest{
		Plan: plan,
	}, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Create() expected error for set attributes failure, got none")
	}
}

// TestDirectoryResource_Read_Success tests successful directory read.
func TestDirectoryResource_Read_Success(t *testing.T) {
	// Create a temp directory with test files.
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("failed to create source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	r := &DirectoryResource{}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	// Build existing state with file hashes.
	fileHashes, _ := types.MapValueFrom(context.Background(), types.StringType, map[string]string{
		"file1.txt": "sha256:abc123",
	})

	data := DirectoryResourceModel{
		Source:          types.StringValue(sourceDir),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		ID:              types.StringValue("192.168.1.100:/remote/dir"),
		SourceHash:      types.StringValue("sha256:old"),
		FileCount:       types.Int64Value(1),
		TotalSize:       types.Int64Value(100),
		FileHashes:      fileHashes,
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, data),
	}

	resp := &resource.ReadResponse{
		State: state,
	}

	r.Read(context.Background(), resource.ReadRequest{
		State: state,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
	}
}

// TestDirectoryResource_Read_SourceNotFound tests read with missing source.
func TestDirectoryResource_Read_SourceNotFound(t *testing.T) {
	r := &DirectoryResource{}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	fileHashes, _ := types.MapValueFrom(context.Background(), types.StringType, map[string]string{})

	data := DirectoryResourceModel{
		Source:          types.StringValue("/nonexistent/source"),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		ID:              types.StringValue("192.168.1.100:/remote/dir"),
		SourceHash:      types.StringValue("sha256:old"),
		FileCount:       types.Int64Value(0),
		TotalSize:       types.Int64Value(0),
		FileHashes:      fileHashes,
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, data),
	}

	resp := &resource.ReadResponse{
		State: state,
	}

	r.Read(context.Background(), resource.ReadRequest{
		State: state,
	}, resp)

	// Should not error, just remove the resource.
	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
	}
}

// TestDirectoryResource_Update_Success tests successful directory update.
func TestDirectoryResource_Update_Success(t *testing.T) {
	// Create a temp directory with test files.
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("failed to create source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("new content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file2.txt"), []byte("unchanged"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := NewMockSSHClient()
	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	// State has old hashes - file1.txt changed, file2.txt unchanged, file3.txt removed
	stateHashes, _ := types.MapValueFrom(context.Background(), types.StringType, map[string]string{
		"file1.txt": "sha256:oldhash1",
		"file2.txt": "sha256:unchanged", // This won't match because we compute real hash
		"file3.txt": "sha256:removed",   // This file no longer exists locally
	})

	stateData := DirectoryResourceModel{
		Source:          types.StringValue(sourceDir),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		ID:              types.StringValue("192.168.1.100:/remote/dir"),
		SourceHash:      types.StringValue("sha256:oldcombined"),
		FileCount:       types.Int64Value(3),
		TotalSize:       types.Int64Value(200),
		FileHashes:      stateHashes,
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	planData := DirectoryResourceModel{
		Source:          types.StringValue(sourceDir),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, stateData),
	}

	plan := tfsdk.Plan{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, planData),
	}

	resp := &resource.UpdateResponse{
		State: state,
	}

	r.Update(context.Background(), resource.UpdateRequest{
		Plan:  plan,
		State: state,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Update() unexpected error: %v", resp.Diagnostics)
	}

	// Should have uploaded changed files.
	if mock.UploadCalls < 1 {
		t.Errorf("expected at least 1 upload call, got %d", mock.UploadCalls)
	}

	// Should have deleted removed file.
	if mock.DeleteCalls < 1 {
		t.Errorf("expected at least 1 delete call, got %d", mock.DeleteCalls)
	}
}

// TestDirectoryResource_Update_SSHConnectionError tests update with SSH connection failure.
func TestDirectoryResource_Update_SSHConnectionError(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("failed to create source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactoryWithError(errors.New("connection refused")),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	stateHashes, _ := types.MapValueFrom(context.Background(), types.StringType, map[string]string{
		"file1.txt": "sha256:oldhash",
	})

	stateData := DirectoryResourceModel{
		Source:          types.StringValue(sourceDir),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		ID:              types.StringValue("192.168.1.100:/remote/dir"),
		SourceHash:      types.StringValue("sha256:old"),
		FileCount:       types.Int64Value(1),
		TotalSize:       types.Int64Value(100),
		FileHashes:      stateHashes,
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	planData := DirectoryResourceModel{
		Source:          types.StringValue(sourceDir),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, stateData),
	}

	plan := tfsdk.Plan{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, planData),
	}

	resp := &resource.UpdateResponse{
		State: state,
	}

	r.Update(context.Background(), resource.UpdateRequest{
		Plan:  plan,
		State: state,
	}, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Update() expected error for SSH connection failure, got none")
	}
}

// TestDirectoryResource_Delete_Success tests successful directory deletion.
func TestDirectoryResource_Delete_Success(t *testing.T) {
	mock := NewMockSSHClient()
	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	fileHashes, _ := types.MapValueFrom(context.Background(), types.StringType, map[string]string{
		"file1.txt": "sha256:hash1",
		"file2.txt": "sha256:hash2",
	})

	data := DirectoryResourceModel{
		Source:          types.StringValue("/source/dir"),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		ID:              types.StringValue("192.168.1.100:/remote/dir"),
		SourceHash:      types.StringValue("sha256:combined"),
		FileCount:       types.Int64Value(2),
		TotalSize:       types.Int64Value(200),
		FileHashes:      fileHashes,
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, data),
	}

	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), resource.DeleteRequest{
		State: state,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Delete() unexpected error: %v", resp.Diagnostics)
	}

	// Should have deleted both files plus tried to delete the directory.
	if mock.DeleteCalls < 2 {
		t.Errorf("expected at least 2 delete calls, got %d", mock.DeleteCalls)
	}
}

// TestDirectoryResource_Delete_SSHConnectionError tests delete with SSH connection failure.
func TestDirectoryResource_Delete_SSHConnectionError(t *testing.T) {
	r := &DirectoryResource{
		sshClientFactory: MockSSHClientFactoryWithError(errors.New("connection refused")),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	fileHashes, _ := types.MapValueFrom(context.Background(), types.StringType, map[string]string{
		"file1.txt": "sha256:hash1",
	})

	data := DirectoryResourceModel{
		Source:          types.StringValue("/source/dir"),
		Destination:     types.StringValue("/remote/dir"),
		Host:            types.StringValue("192.168.1.100"),
		SSHUser:         types.StringValue("root"),
		SSHPort:         types.Int64Value(22),
		Owner:           types.StringValue("root"),
		Group:           types.StringValue("root"),
		Mode:            types.StringValue("0644"),
		ID:              types.StringValue("192.168.1.100:/remote/dir"),
		SourceHash:      types.StringValue("sha256:combined"),
		FileCount:       types.Int64Value(1),
		TotalSize:       types.Int64Value(100),
		FileHashes:      fileHashes,
		Exclude:         types.ListNull(types.StringType),
		ParallelUploads: types.Int64Value(4),
		SymlinkPolicy:   types.StringValue("follow"),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    buildDirectoryTerraformValue(t, schemaResp.Schema, data),
	}

	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), resource.DeleteRequest{
		State: state,
	}, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Delete() expected error for SSH connection failure, got none")
	}
}
