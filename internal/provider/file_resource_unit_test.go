package provider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// TestFileResource_CreateSSHClient tests the createSSHClient method with various configurations.
func TestFileResource_CreateSSHClient(t *testing.T) {
	tests := []struct {
		name           string
		providerConfig *FilesyncProviderModel
		data           *FileResourceModel
		factoryErr     error
		wantErr        bool
	}{
		{
			name: "basic connection",
			data: &FileResourceModel{
				Host:    types.StringValue("192.168.1.100"),
				SSHPort: types.Int64Value(22),
				SSHUser: types.StringValue("testuser"),
			},
			wantErr: false,
		},
		{
			name:       "connection error",
			factoryErr: errors.New("connection failed"),
			data: &FileResourceModel{
				Host:    types.StringValue("192.168.1.100"),
				SSHPort: types.Int64Value(22),
				SSHUser: types.StringValue("testuser"),
			},
			wantErr: true,
		},
		{
			name: "with provider defaults",
			providerConfig: &FilesyncProviderModel{
				SSHUser:     types.StringValue("provider-user"),
				SSHKeyPath:  types.StringValue("~/.ssh/id_rsa"),
				SSHPort:     types.Int64Value(2222),
				SSHPassword: types.StringValue("provider-pass"),
			},
			data: &FileResourceModel{
				Host:    types.StringValue("192.168.1.100"),
				SSHPort: types.Int64Value(22),
				SSHUser: types.StringValue("root"),
			},
			wantErr: false,
		},
		{
			name: "with bastion host",
			data: &FileResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				SSHPort:     types.Int64Value(22),
				SSHUser:     types.StringValue("root"),
				BastionHost: types.StringValue("bastion.example.com"),
				BastionPort: types.Int64Value(22),
				BastionUser: types.StringValue("bastion-user"),
			},
			wantErr: false,
		},
		{
			name: "with certificate",
			data: &FileResourceModel{
				Host:           types.StringValue("192.168.1.100"),
				SSHPort:        types.Int64Value(22),
				SSHUser:        types.StringValue("root"),
				SSHPrivateKey:  types.StringValue("private-key-content"),
				SSHCertificate: types.StringValue("cert-content"),
			},
			wantErr: false,
		},
		{
			name: "with certificate path",
			data: &FileResourceModel{
				Host:               types.StringValue("192.168.1.100"),
				SSHPort:            types.Int64Value(22),
				SSHUser:            types.StringValue("root"),
				SSHKeyPath:         types.StringValue("~/.ssh/id_rsa"),
				SSHCertificatePath: types.StringValue("~/.ssh/id_rsa-cert.pub"),
			},
			wantErr: false,
		},
		{
			name: "with provider certificate",
			providerConfig: &FilesyncProviderModel{
				SSHPrivateKey:  types.StringValue("provider-key"),
				SSHCertificate: types.StringValue("provider-cert"),
			},
			data: &FileResourceModel{
				Host:    types.StringValue("192.168.1.100"),
				SSHPort: types.Int64Value(22),
				SSHUser: types.StringValue("root"),
			},
			wantErr: false,
		},
		{
			name: "with provider bastion",
			providerConfig: &FilesyncProviderModel{
				SSHKeyPath:  types.StringValue("~/.ssh/id_rsa"),
				BastionHost: types.StringValue("provider-bastion.example.com"),
				BastionPort: types.Int64Value(22),
				BastionUser: types.StringValue("provider-bastion-user"),
				BastionKey:  types.StringValue("provider-bastion-key"),
			},
			data: &FileResourceModel{
				Host:    types.StringValue("192.168.1.100"),
				SSHPort: types.Int64Value(22),
				SSHUser: types.StringValue("root"),
			},
			wantErr: false,
		},
		{
			name: "with provider bastion key path",
			providerConfig: &FilesyncProviderModel{
				SSHKeyPath:      types.StringValue("~/.ssh/id_rsa"),
				BastionKeyPath:  types.StringValue("~/.ssh/bastion_key"),
				BastionPassword: types.StringValue("bastion-password"),
			},
			data: &FileResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				SSHPort:     types.Int64Value(22),
				SSHUser:     types.StringValue("root"),
				BastionHost: types.StringValue("bastion.example.com"),
				BastionPort: types.Int64Value(22),
				BastionUser: types.StringValue("bastion-user"),
			},
			wantErr: false,
		},
		{
			name: "with provider certificate path",
			providerConfig: &FilesyncProviderModel{
				SSHKeyPath:         types.StringValue("~/.ssh/id_rsa"),
				SSHCertificatePath: types.StringValue("~/.ssh/id_rsa-cert.pub"),
			},
			data: &FileResourceModel{
				Host:    types.StringValue("192.168.1.100"),
				SSHPort: types.Int64Value(22),
				SSHUser: types.StringValue("root"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *FileResource
			if tt.factoryErr != nil {
				r = &FileResource{
					providerConfig:   tt.providerConfig,
					sshClientFactory: MockSSHClientFactoryWithError(tt.factoryErr),
				}
			} else {
				r = &FileResource{
					providerConfig:   tt.providerConfig,
					sshClientFactory: MockSSHClientFactory(NewMockSSHClient()),
				}
			}

			client, err := r.createSSHClient(tt.data)

			if tt.wantErr {
				if err == nil {
					t.Error("createSSHClient() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("createSSHClient() unexpected error: %v", err)
			}
			if client == nil {
				t.Error("createSSHClient() returned nil client")
			}
		})
	}
}

// TestFileResource_InsecureIgnoreHostKey tests that the insecure_ignore_host_key setting
// is properly passed through to the SSH client config at resource and provider levels.
func TestFileResource_InsecureIgnoreHostKey(t *testing.T) {
	tests := []struct {
		name                      string
		providerConfig            *FilesyncProviderModel
		data                      *FileResourceModel
		wantInsecureIgnoreHostKey bool
	}{
		{
			name: "resource level insecure_ignore_host_key = true",
			data: &FileResourceModel{
				Host:                  types.StringValue("192.168.1.100"),
				SSHPort:               types.Int64Value(22),
				SSHUser:               types.StringValue("root"),
				SSHKeyPath:            types.StringValue("~/.ssh/id_ed25519"),
				InsecureIgnoreHostKey: types.BoolValue(true),
			},
			wantInsecureIgnoreHostKey: true,
		},
		{
			name: "resource level insecure_ignore_host_key = false (explicit)",
			data: &FileResourceModel{
				Host:                  types.StringValue("192.168.1.100"),
				SSHPort:               types.Int64Value(22),
				SSHUser:               types.StringValue("root"),
				SSHKeyPath:            types.StringValue("~/.ssh/id_ed25519"),
				InsecureIgnoreHostKey: types.BoolValue(false),
			},
			wantInsecureIgnoreHostKey: false,
		},
		{
			name: "resource level insecure_ignore_host_key not set (null)",
			data: &FileResourceModel{
				Host:                  types.StringValue("192.168.1.100"),
				SSHPort:               types.Int64Value(22),
				SSHUser:               types.StringValue("root"),
				SSHKeyPath:            types.StringValue("~/.ssh/id_ed25519"),
				InsecureIgnoreHostKey: types.BoolNull(),
			},
			wantInsecureIgnoreHostKey: false,
		},
		{
			name: "provider level insecure_ignore_host_key = true, resource not set",
			providerConfig: &FilesyncProviderModel{
				SSHKeyPath:            types.StringValue("~/.ssh/id_ed25519"),
				InsecureIgnoreHostKey: types.BoolValue(true),
			},
			data: &FileResourceModel{
				Host:                  types.StringValue("192.168.1.100"),
				SSHPort:               types.Int64Value(22),
				SSHUser:               types.StringValue("root"),
				InsecureIgnoreHostKey: types.BoolNull(), // Not set at resource level
			},
			wantInsecureIgnoreHostKey: true,
		},
		{
			name: "resource level overrides provider level (resource=true, provider=false)",
			providerConfig: &FilesyncProviderModel{
				SSHKeyPath:            types.StringValue("~/.ssh/id_ed25519"),
				InsecureIgnoreHostKey: types.BoolValue(false),
			},
			data: &FileResourceModel{
				Host:                  types.StringValue("192.168.1.100"),
				SSHPort:               types.Int64Value(22),
				SSHUser:               types.StringValue("root"),
				InsecureIgnoreHostKey: types.BoolValue(true),
			},
			wantInsecureIgnoreHostKey: true,
		},
		{
			name: "resource level overrides provider level (resource=false, provider=true)",
			providerConfig: &FilesyncProviderModel{
				SSHKeyPath:            types.StringValue("~/.ssh/id_ed25519"),
				InsecureIgnoreHostKey: types.BoolValue(true),
			},
			data: &FileResourceModel{
				Host:                  types.StringValue("192.168.1.100"),
				SSHPort:               types.Int64Value(22),
				SSHUser:               types.StringValue("root"),
				InsecureIgnoreHostKey: types.BoolValue(false),
			},
			// Resource explicitly sets false, which should override provider's true.
			// This ensures users can enable host key checking at the resource level
			// even if the provider has it disabled globally.
			wantInsecureIgnoreHostKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := &ConfigCapturingFactory{
				Mock: NewMockSSHClient(),
			}
			r := &FileResource{
				providerConfig:   tt.providerConfig,
				sshClientFactory: factory.Factory(),
			}

			_, err := r.createSSHClient(tt.data)
			if err != nil {
				t.Fatalf("createSSHClient() unexpected error: %v", err)
			}

			if factory.CapturedConfig.InsecureIgnoreHostKey != tt.wantInsecureIgnoreHostKey {
				t.Errorf("InsecureIgnoreHostKey = %v, want %v",
					factory.CapturedConfig.InsecureIgnoreHostKey, tt.wantInsecureIgnoreHostKey)
			}
		})
	}
}

// TestFileResource_ImportState_ValidID tests valid import ID parsing.
func TestFileResource_ImportState_ValidID(t *testing.T) {
	tests := []struct {
		name        string
		importID    string
		wantHost    string
		wantDest    string
		shouldError bool
	}{
		{
			name:        "simple host and path",
			importID:    "192.168.1.100:/etc/app/config.json",
			wantHost:    "192.168.1.100",
			wantDest:    "/etc/app/config.json",
			shouldError: false,
		},
		{
			name:        "hostname with path",
			importID:    "server.example.com:/var/www/index.html",
			wantHost:    "server.example.com",
			wantDest:    "/var/www/index.html",
			shouldError: false,
		},
		{
			name:        "root path",
			importID:    "localhost:/file.txt",
			wantHost:    "localhost",
			wantDest:    "/file.txt",
			shouldError: false,
		},
		{
			name:        "missing colon",
			importID:    "192.168.1.100/etc/app/config.json",
			shouldError: true,
		},
		{
			name:        "no host",
			importID:    ":/etc/app/config.json",
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
			r := &FileResource{}

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

// TestFileResource_Configure tests the Configure method with various inputs.
func TestFileResource_Configure(t *testing.T) {
	tests := []struct {
		name         string
		providerData interface{}
		wantErr      bool
		checkConfig  bool // whether to verify providerConfig was set
	}{
		{
			name:         "nil provider data",
			providerData: nil,
			wantErr:      false,
			checkConfig:  false,
		},
		{
			name: "valid provider data",
			providerData: &FilesyncProviderModel{
				SSHUser: types.StringValue("testuser"),
			},
			wantErr:     false,
			checkConfig: true,
		},
		{
			name:         "wrong type - string",
			providerData: "wrong type",
			wantErr:      true,
			checkConfig:  false,
		},
		{
			name:         "wrong type - int",
			providerData: 42,
			wantErr:      true,
			checkConfig:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &FileResource{}
			resp := &resource.ConfigureResponse{}

			r.Configure(context.Background(), resource.ConfigureRequest{
				ProviderData: tt.providerData,
			}, resp)

			if tt.wantErr {
				if !resp.Diagnostics.HasError() {
					t.Error("Configure() expected error, got none")
				}
				return
			}

			if resp.Diagnostics.HasError() {
				t.Errorf("Configure() unexpected error: %v", resp.Diagnostics)
				return
			}

			if tt.checkConfig {
				if r.providerConfig != tt.providerData {
					t.Error("Configure() did not set providerConfig correctly")
				}
			}
		})
	}
}

// TestHashFileUnit tests the hashFile function with various file types.
func TestHashFileUnit(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		content  []byte
	}{
		{
			name:     "binary content",
			filename: "binary.bin",
			content:  []byte{0x00, 0x01, 0x02, 0xff, 0xfe},
		},
		{
			name:     "unicode content",
			filename: "unicode.txt",
			content:  []byte("héllo wörld 你好世界 🌍"),
		},
		{
			name:     "empty file",
			filename: "empty.txt",
			content:  []byte{},
		},
		{
			name:     "large content",
			filename: "large.txt",
			content:  make([]byte, 1024*10), // 10KB
		},
		{
			name:     "newlines only",
			filename: "newlines.txt",
			content:  []byte("\n\n\n\n\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			filePath := filepath.Join(tmpDir, tt.filename)

			if err := os.WriteFile(filePath, tt.content, 0644); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}

			hash, size, err := hashFile(filePath)
			if err != nil {
				t.Fatalf("hashFile() error: %v", err)
			}

			if size != int64(len(tt.content)) {
				t.Errorf("hashFile() size = %d, want %d", size, len(tt.content))
			}

			if len(hash) < 7 || hash[:7] != "sha256:" {
				t.Error("hashFile() hash should have sha256: prefix")
			}
		})
	}
}

// TestHashFileErrors tests hashFile error conditions.
func TestHashFileErrors(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "non-existent file",
			path:    "/nonexistent/path/file.txt",
			wantErr: true,
		},
		{
			name:    "directory instead of file",
			path:    os.TempDir(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := hashFile(tt.path)
			if tt.wantErr && err == nil {
				t.Error("hashFile() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("hashFile() unexpected error: %v", err)
			}
		})
	}
}

// TestExpandPathUnit tests edge cases for expandPath.
func TestExpandPathUnit(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"path with spaces", "/path/with spaces/file.txt"},
		{"path with dots", "/path/../other/./file.txt"},
		{"unicode path", "/путь/文件/file.txt"},
		{"very long path", "/" + string(make([]byte, 200))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just ensure it doesn't panic.
			result := ExpandPath(tt.input)
			if result == "" && tt.input != "" {
				t.Error("ExpandPath() returned empty for non-empty input")
			}
		})
	}
}

// TestFileResource_Create_Success tests successful file creation.
func TestFileResource_Create_Success(t *testing.T) {
	// Create a temp source file.
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	sourceContent := []byte("test content for create")
	if err := os.WriteFile(sourceFile, sourceContent, 0644); err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}

	mock := NewMockSSHClient()
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	// Build plan data.
	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		Mode:        types.StringValue("0644"),
		Owner:       types.StringValue("root"),
		Group:       types.StringValue("root"),
	}

	// Create schema for state.
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	// Build request with plan.
	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.CreateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
	}

	resp := &resource.CreateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Create() unexpected error: %v", resp.Diagnostics)
		return
	}

	// Verify mock was called.
	if mock.UploadCalls != 1 {
		t.Errorf("expected 1 upload call, got %d", mock.UploadCalls)
	}
	if mock.SetAttributeCalls != 1 {
		t.Errorf("expected 1 set attribute call, got %d", mock.SetAttributeCalls)
	}
}

// TestFileResource_Create_SourceFileError tests create with missing source file.
func TestFileResource_Create_SourceFileError(t *testing.T) {
	mock := NewMockSSHClient()
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue("/nonexistent/source.txt"),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.CreateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
	}

	resp := &resource.CreateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Create(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Create() expected error for missing source file")
	}
}

// TestFileResource_Create_SSHConnectionError tests create with SSH connection error.
func TestFileResource_Create_SSHConnectionError(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	r := &FileResource{
		sshClientFactory: MockSSHClientFactoryWithError(errors.New("connection refused")),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.CreateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
	}

	resp := &resource.CreateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Create(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Create() expected error for SSH connection failure")
	}
}

// TestFileResource_Create_UploadError tests create with upload error.
func TestFileResource_Create_UploadError(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockSSHClient()
	mock.UploadError = errors.New("upload failed: permission denied")
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.CreateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
	}

	resp := &resource.CreateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Create(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Create() expected error for upload failure")
	}
}

// TestFileResource_Create_SetAttributesError tests create with attribute setting error.
func TestFileResource_Create_SetAttributesError(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockSSHClient()
	mock.SetAttributeError = errors.New("chown failed: permission denied")
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		Owner:       types.StringValue("root"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.CreateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
	}

	resp := &resource.CreateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Create(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Create() expected error for set attributes failure")
	}
}

// TestFileResource_Read_Success tests successful read operation.
func TestFileResource_Read_Success(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("existing content"), 0644); err != nil {
		t.Fatal(err)
	}

	r := &FileResource{}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	stateVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.ReadRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
	}
}

// TestFileResource_Read_SourceDeleted tests read when source file is deleted.
func TestFileResource_Read_SourceDeleted(t *testing.T) {
	r := &FileResource{}

	data := FileResourceModel{
		Source:      types.StringValue("/nonexistent/deleted.txt"),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	stateVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.ReadRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	r.Read(context.Background(), req, resp)

	// Should not error but should remove from state.
	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error for deleted source: %v", resp.Diagnostics)
	}
}

// TestFileResource_Delete_Success tests successful delete operation.
func TestFileResource_Delete_Success(t *testing.T) {
	mock := NewMockSSHClient()
	mock.ExistingFiles["/remote/test.txt"] = true
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue("/local/source.txt"),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	stateVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.DeleteRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Delete() unexpected error: %v", resp.Diagnostics)
	}

	if mock.DeleteCalls != 1 {
		t.Errorf("expected 1 delete call, got %d", mock.DeleteCalls)
	}
}

// TestFileResource_Delete_SSHError tests delete with SSH connection error.
func TestFileResource_Delete_SSHError(t *testing.T) {
	r := &FileResource{
		sshClientFactory: MockSSHClientFactoryWithError(errors.New("connection refused")),
	}

	data := FileResourceModel{
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	stateVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.DeleteRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Delete() expected error for SSH connection failure")
	}
}

// TestFileResource_Delete_RemoteError tests delete with remote deletion error.
func TestFileResource_Delete_RemoteError(t *testing.T) {
	mock := NewMockSSHClient()
	mock.DeleteError = errors.New("permission denied")
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	stateVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.DeleteRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Delete() expected error for remote deletion failure")
	}
}

// TestFileResource_Update_Success tests successful update operation.
func TestFileResource_Update_Success(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("updated content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockSSHClient()
	// Set up mock to return expected hash (simulating no drift).
	mock.FileHashes["/remote/test.txt"] = "sha256:originalhash"
	mock.ExistingFiles["/remote/test.txt"] = true
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
		SourceHash:  types.StringValue("sha256:originalhash"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	stateVal := buildTerraformValue(t, schemaResp.Schema, data)

	req := resource.UpdateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.UpdateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Update() unexpected error: %v", resp.Diagnostics)
	}

	if mock.UploadCalls != 1 {
		t.Errorf("expected 1 upload call, got %d", mock.UploadCalls)
	}
}

// TestFileResource_Update_DriftDetected tests update when remote file has drifted.
func TestFileResource_Update_DriftDetected(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("local content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockSSHClient()
	// Remote has different hash - drift detected.
	mock.FileHashes["/remote/test.txt"] = "sha256:remotehash"
	mock.FileContents["/remote/test.txt"] = []byte("remote modified content")
	mock.ExistingFiles["/remote/test.txt"] = true
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
		SourceHash:  types.StringValue("sha256:expectedhash"), // Different from remote
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	stateVal := buildTerraformValue(t, schemaResp.Schema, data)

	req := resource.UpdateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.UpdateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Update(context.Background(), req, resp)

	// Should error due to drift.
	if !resp.Diagnostics.HasError() {
		t.Error("Update() expected drift error")
	}
}

// TestFileResource_Update_SSHError tests update with SSH connection error.
func TestFileResource_Update_SSHError(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	r := &FileResource{
		sshClientFactory: MockSSHClientFactoryWithError(errors.New("connection refused")),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	stateVal := buildTerraformValue(t, schemaResp.Schema, data)

	req := resource.UpdateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.UpdateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Update(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Update() expected error for SSH connection failure")
	}
}

// TestFileResource_Update_UploadError tests update with upload error.
func TestFileResource_Update_UploadError(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockSSHClient()
	mock.FileHashes["/remote/test.txt"] = "sha256:originalhash"
	mock.UploadError = errors.New("upload failed")
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		SourceHash:  types.StringValue("sha256:originalhash"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	stateVal := buildTerraformValue(t, schemaResp.Schema, data)

	req := resource.UpdateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.UpdateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Update(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("Update() expected error for upload failure")
	}
}

// buildTerraformValue is a helper to build terraform values for testing.
func buildTerraformValue(t *testing.T, s schema.Schema, data FileResourceModel) tftypes.Value {
	t.Helper()

	attrTypes := s.Type().TerraformType(context.Background())

	// Helper to convert string to value or nil for empty.
	strVal := func(s types.String) interface{} {
		if s.IsNull() || s.IsUnknown() {
			return nil
		}
		return s.ValueString()
	}

	// Helper to convert int64 to value or nil.
	intVal := func(i types.Int64) interface{} {
		if i.IsNull() || i.IsUnknown() {
			return nil
		}
		return i.ValueInt64Pointer()
	}

	// Helper to convert bool to value or nil.
	boolVal := func(b types.Bool) interface{} {
		if b.IsNull() || b.IsUnknown() {
			return nil
		}
		return b.ValueBool()
	}

	vals := map[string]tftypes.Value{
		"id":                       tftypes.NewValue(tftypes.String, strVal(data.ID)),
		"source":                   tftypes.NewValue(tftypes.String, strVal(data.Source)),
		"destination":              tftypes.NewValue(tftypes.String, strVal(data.Destination)),
		"host":                     tftypes.NewValue(tftypes.String, strVal(data.Host)),
		"ssh_port":                 tftypes.NewValue(tftypes.Number, intVal(data.SSHPort)),
		"ssh_user":                 tftypes.NewValue(tftypes.String, strVal(data.SSHUser)),
		"ssh_key_path":             tftypes.NewValue(tftypes.String, strVal(data.SSHKeyPath)),
		"ssh_private_key":          tftypes.NewValue(tftypes.String, strVal(data.SSHPrivateKey)),
		"ssh_password":             tftypes.NewValue(tftypes.String, strVal(data.SSHPassword)),
		"ssh_certificate":          tftypes.NewValue(tftypes.String, strVal(data.SSHCertificate)),
		"ssh_certificate_path":     tftypes.NewValue(tftypes.String, strVal(data.SSHCertificatePath)),
		"mode":                     tftypes.NewValue(tftypes.String, strVal(data.Mode)),
		"owner":                    tftypes.NewValue(tftypes.String, strVal(data.Owner)),
		"group":                    tftypes.NewValue(tftypes.String, strVal(data.Group)),
		"bastion_host":             tftypes.NewValue(tftypes.String, strVal(data.BastionHost)),
		"bastion_port":             tftypes.NewValue(tftypes.Number, intVal(data.BastionPort)),
		"bastion_user":             tftypes.NewValue(tftypes.String, strVal(data.BastionUser)),
		"bastion_private_key":      tftypes.NewValue(tftypes.String, strVal(data.BastionKey)),
		"bastion_key_path":         tftypes.NewValue(tftypes.String, strVal(data.BastionKeyPath)),
		"bastion_password":         tftypes.NewValue(tftypes.String, strVal(data.BastionPassword)),
		"insecure_ignore_host_key": tftypes.NewValue(tftypes.Bool, boolVal(data.InsecureIgnoreHostKey)),
		"known_hosts_file":         tftypes.NewValue(tftypes.String, strVal(data.KnownHostsFile)),
		"strict_host_key_checking": tftypes.NewValue(tftypes.String, strVal(data.StrictHostKeyChecking)),
		"check_remote_on_plan":     tftypes.NewValue(tftypes.Bool, boolVal(data.CheckRemoteOnPlan)),
		"import_syncs_local":       tftypes.NewValue(tftypes.Bool, boolVal(data.ImportSyncsLocal)),
		"host_agnostic_id":         tftypes.NewValue(tftypes.Bool, boolVal(data.HostAgnosticID)),
		"source_hash":              tftypes.NewValue(tftypes.String, strVal(data.SourceHash)),
		"size":                     tftypes.NewValue(tftypes.Number, intVal(data.Size)),
	}

	return tftypes.NewValue(attrTypes, vals)
}

// TestSourceHashPlanModifier tests the sourceHashPlanModifier.
func TestSourceHashPlanModifier(t *testing.T) {
	t.Run("description", func(t *testing.T) {
		m := sourceHashPlanModifier{}
		desc := m.Description(context.Background())
		if desc == "" {
			t.Error("Description should not be empty")
		}
		mdDesc := m.MarkdownDescription(context.Background())
		if mdDesc == "" {
			t.Error("MarkdownDescription should not be empty")
		}
	})

	t.Run("computes hash for existing file", func(t *testing.T) {
		// Create a temp file.
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		m := sourceHashPlanModifier{}

		// Create a plan with the source attribute.
		planVal := tftypes.NewValue(tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"source":      tftypes.String,
				"source_hash": tftypes.String,
			},
		}, map[string]tftypes.Value{
			"source":      tftypes.NewValue(tftypes.String, testFile),
			"source_hash": tftypes.NewValue(tftypes.String, nil),
		})

		planSchema := schema.Schema{
			Attributes: map[string]schema.Attribute{
				"source":      schema.StringAttribute{},
				"source_hash": schema.StringAttribute{Computed: true},
			},
		}

		plan := tfsdk.Plan{
			Raw:    planVal,
			Schema: planSchema,
		}

		req := planmodifier.StringRequest{
			Plan:       plan,
			PlanValue:  types.StringNull(),
			StateValue: types.StringValue("old-hash"),
		}
		resp := &planmodifier.StringResponse{}

		m.PlanModifyString(context.Background(), req, resp)

		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error: %v", resp.Diagnostics)
		}

		// Should compute a hash.
		if resp.PlanValue.IsNull() || resp.PlanValue.IsUnknown() {
			t.Error("expected a computed hash value")
		}

		hash := resp.PlanValue.ValueString()
		if len(hash) == 0 || hash[:7] != "sha256:" {
			t.Errorf("expected sha256 hash, got: %s", hash)
		}
	})

	t.Run("returns unknown for missing file", func(t *testing.T) {
		m := sourceHashPlanModifier{}

		planVal := tftypes.NewValue(tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"source":      tftypes.String,
				"source_hash": tftypes.String,
			},
		}, map[string]tftypes.Value{
			"source":      tftypes.NewValue(tftypes.String, "/nonexistent/file.txt"),
			"source_hash": tftypes.NewValue(tftypes.String, nil),
		})

		planSchema := schema.Schema{
			Attributes: map[string]schema.Attribute{
				"source":      schema.StringAttribute{},
				"source_hash": schema.StringAttribute{Computed: true},
			},
		}

		plan := tfsdk.Plan{
			Raw:    planVal,
			Schema: planSchema,
		}

		req := planmodifier.StringRequest{
			Plan:      plan,
			PlanValue: types.StringNull(),
		}
		resp := &planmodifier.StringResponse{}

		m.PlanModifyString(context.Background(), req, resp)

		if !resp.PlanValue.IsUnknown() {
			t.Error("expected unknown value for missing file")
		}
	})

	t.Run("skips on destroy", func(t *testing.T) {
		m := sourceHashPlanModifier{}

		// Null plan means destroy.
		req := planmodifier.StringRequest{
			Plan: tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil)},
		}
		resp := &planmodifier.StringResponse{
			PlanValue: types.StringValue("original"),
		}

		m.PlanModifyString(context.Background(), req, resp)

		// Should not modify the value.
		if resp.PlanValue.ValueString() != "original" {
			t.Error("should not modify value on destroy")
		}
	})
}

// TestFileResource_CheckRemoteDrift tests the checkRemoteDrift method.
func TestFileResource_CheckRemoteDrift(t *testing.T) {
	tests := []struct {
		name           string
		data           *FileResourceModel
		mockSetup      func(*MockSSHClient)
		factoryErr     error
		wantDrift      bool
		wantRemoteHash string
		wantErr        bool
	}{
		{
			name: "check_remote_on_plan disabled - no check performed",
			data: &FileResourceModel{
				Host:              types.StringValue("192.168.1.100"),
				Destination:       types.StringValue("/remote/test.txt"),
				SSHPort:           types.Int64Value(22),
				SSHUser:           types.StringValue("root"),
				SourceHash:        types.StringValue("sha256:abc123"),
				CheckRemoteOnPlan: types.BoolValue(false),
			},
			mockSetup: func(m *MockSSHClient) {
				// Should not be called
			},
			wantDrift:      false,
			wantRemoteHash: "",
			wantErr:        false,
		},
		{
			name: "check_remote_on_plan null - no check performed",
			data: &FileResourceModel{
				Host:              types.StringValue("192.168.1.100"),
				Destination:       types.StringValue("/remote/test.txt"),
				SSHPort:           types.Int64Value(22),
				SSHUser:           types.StringValue("root"),
				SourceHash:        types.StringValue("sha256:abc123"),
				CheckRemoteOnPlan: types.BoolNull(),
			},
			mockSetup: func(m *MockSSHClient) {},
			wantDrift: false,
			wantErr:   false,
		},
		{
			name: "no state hash - skip check",
			data: &FileResourceModel{
				Host:              types.StringValue("192.168.1.100"),
				Destination:       types.StringValue("/remote/test.txt"),
				SSHPort:           types.Int64Value(22),
				SSHUser:           types.StringValue("root"),
				SourceHash:        types.StringNull(),
				CheckRemoteOnPlan: types.BoolValue(true),
			},
			mockSetup: func(m *MockSSHClient) {},
			wantDrift: false,
			wantErr:   false,
		},
		{
			name: "no drift - hashes match",
			data: &FileResourceModel{
				Host:              types.StringValue("192.168.1.100"),
				Destination:       types.StringValue("/remote/test.txt"),
				SSHPort:           types.Int64Value(22),
				SSHUser:           types.StringValue("root"),
				SourceHash:        types.StringValue("sha256:abc123"),
				CheckRemoteOnPlan: types.BoolValue(true),
			},
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/test.txt"] = true
				m.FileHashes["/remote/test.txt"] = "sha256:abc123"
			},
			wantDrift:      false,
			wantRemoteHash: "sha256:abc123",
			wantErr:        false,
		},
		{
			name: "drift detected - hashes differ",
			data: &FileResourceModel{
				Host:              types.StringValue("192.168.1.100"),
				Destination:       types.StringValue("/remote/test.txt"),
				SSHPort:           types.Int64Value(22),
				SSHUser:           types.StringValue("root"),
				SourceHash:        types.StringValue("sha256:abc123"),
				CheckRemoteOnPlan: types.BoolValue(true),
			},
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/test.txt"] = true
				m.FileHashes["/remote/test.txt"] = "sha256:def456"
			},
			wantDrift:      true,
			wantRemoteHash: "sha256:def456",
			wantErr:        false,
		},
		{
			name: "drift detected - remote file deleted",
			data: &FileResourceModel{
				Host:              types.StringValue("192.168.1.100"),
				Destination:       types.StringValue("/remote/test.txt"),
				SSHPort:           types.Int64Value(22),
				SSHUser:           types.StringValue("root"),
				SourceHash:        types.StringValue("sha256:abc123"),
				CheckRemoteOnPlan: types.BoolValue(true),
			},
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/test.txt"] = false
			},
			wantDrift:      true,
			wantRemoteHash: "",
			wantErr:        false,
		},
		{
			name: "SSH connection error",
			data: &FileResourceModel{
				Host:              types.StringValue("192.168.1.100"),
				Destination:       types.StringValue("/remote/test.txt"),
				SSHPort:           types.Int64Value(22),
				SSHUser:           types.StringValue("root"),
				SourceHash:        types.StringValue("sha256:abc123"),
				CheckRemoteOnPlan: types.BoolValue(true),
			},
			factoryErr: errors.New("connection refused"),
			wantDrift:  false,
			wantErr:    true,
		},
		{
			name: "file exists check error",
			data: &FileResourceModel{
				Host:              types.StringValue("192.168.1.100"),
				Destination:       types.StringValue("/remote/test.txt"),
				SSHPort:           types.Int64Value(22),
				SSHUser:           types.StringValue("root"),
				SourceHash:        types.StringValue("sha256:abc123"),
				CheckRemoteOnPlan: types.BoolValue(true),
			},
			mockSetup: func(m *MockSSHClient) {
				m.ExistsError = errors.New("permission denied")
			},
			wantDrift: false,
			wantErr:   true,
		},
		{
			name: "get hash error",
			data: &FileResourceModel{
				Host:              types.StringValue("192.168.1.100"),
				Destination:       types.StringValue("/remote/test.txt"),
				SSHPort:           types.Int64Value(22),
				SSHUser:           types.StringValue("root"),
				SourceHash:        types.StringValue("sha256:abc123"),
				CheckRemoteOnPlan: types.BoolValue(true),
			},
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/test.txt"] = true
				m.GetHashError = errors.New("hash computation failed")
			},
			wantDrift: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *FileResource
			if tt.factoryErr != nil {
				r = &FileResource{
					sshClientFactory: MockSSHClientFactoryWithError(tt.factoryErr),
				}
			} else {
				mock := NewMockSSHClient()
				if tt.mockSetup != nil {
					tt.mockSetup(mock)
				}
				r = &FileResource{
					sshClientFactory: MockSSHClientFactory(mock),
				}
			}

			hasDrift, remoteHash, err := r.checkRemoteDrift(context.Background(), tt.data)

			if tt.wantErr {
				if err == nil {
					t.Error("checkRemoteDrift() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("checkRemoteDrift() unexpected error: %v", err)
				return
			}

			if hasDrift != tt.wantDrift {
				t.Errorf("checkRemoteDrift() hasDrift = %v, want %v", hasDrift, tt.wantDrift)
			}
			if remoteHash != tt.wantRemoteHash {
				t.Errorf("checkRemoteDrift() remoteHash = %v, want %v", remoteHash, tt.wantRemoteHash)
			}
		})
	}
}

// TestFileResource_SyncLocalFromRemote tests the syncLocalFromRemote method.
func TestFileResource_SyncLocalFromRemote(t *testing.T) {
	tests := []struct {
		name       string
		data       *FileResourceModel
		mockSetup  func(*MockSSHClient)
		factoryErr error
		wantErr    bool
		checkFile  bool // whether to verify local file was created
	}{
		{
			name: "successful sync",
			data: &FileResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				Destination: types.StringValue("/remote/config.json"),
				SSHPort:     types.Int64Value(22),
				SSHUser:     types.StringValue("root"),
				// Source will be set in test
			},
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/config.json"] = true
				m.FileContents["/remote/config.json"] = []byte(`{"key": "value"}`)
			},
			wantErr:   false,
			checkFile: true,
		},
		{
			name: "source path not set",
			data: &FileResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				Destination: types.StringValue("/remote/config.json"),
				SSHPort:     types.Int64Value(22),
				SSHUser:     types.StringValue("root"),
				Source:      types.StringValue(""),
			},
			mockSetup: func(m *MockSSHClient) {},
			wantErr:   true,
			checkFile: false,
		},
		{
			name: "SSH connection error",
			data: &FileResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				Destination: types.StringValue("/remote/config.json"),
				SSHPort:     types.Int64Value(22),
				SSHUser:     types.StringValue("root"),
				// Source will be set in test
			},
			factoryErr: errors.New("connection refused"),
			wantErr:    true,
			checkFile:  false,
		},
		{
			name: "remote file does not exist",
			data: &FileResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				Destination: types.StringValue("/remote/config.json"),
				SSHPort:     types.Int64Value(22),
				SSHUser:     types.StringValue("root"),
				// Source will be set in test
			},
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/config.json"] = false
			},
			wantErr:   true,
			checkFile: false,
		},
		{
			name: "file exists check error",
			data: &FileResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				Destination: types.StringValue("/remote/config.json"),
				SSHPort:     types.Int64Value(22),
				SSHUser:     types.StringValue("root"),
				// Source will be set in test
			},
			mockSetup: func(m *MockSSHClient) {
				m.ExistsError = errors.New("permission denied")
			},
			wantErr:   true,
			checkFile: false,
		},
		{
			name: "read content error",
			data: &FileResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				Destination: types.StringValue("/remote/config.json"),
				SSHPort:     types.Int64Value(22),
				SSHUser:     types.StringValue("root"),
				// Source will be set in test
			},
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/config.json"] = true
				m.ReadContentError = errors.New("read failed")
			},
			wantErr:   true,
			checkFile: false,
		},
		{
			name: "creates parent directories",
			data: &FileResourceModel{
				Host:        types.StringValue("192.168.1.100"),
				Destination: types.StringValue("/remote/config.json"),
				SSHPort:     types.Int64Value(22),
				SSHUser:     types.StringValue("root"),
				// Source will be set to a nested path
			},
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/config.json"] = true
				m.FileContents["/remote/config.json"] = []byte(`nested content`)
			},
			wantErr:   false,
			checkFile: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			var sourcePath string

			// Set source path for tests that need it
			if tt.data.Source.IsNull() || tt.data.Source.ValueString() == "" {
				if tt.name != "source path not set" {
					if tt.name == "creates parent directories" {
						sourcePath = filepath.Join(tmpDir, "nested", "dir", "config.json")
					} else {
						sourcePath = filepath.Join(tmpDir, "local-config.json")
					}
					tt.data.Source = types.StringValue(sourcePath)
				}
			} else {
				sourcePath = tt.data.Source.ValueString()
			}

			var r *FileResource
			if tt.factoryErr != nil {
				r = &FileResource{
					sshClientFactory: MockSSHClientFactoryWithError(tt.factoryErr),
				}
			} else {
				mock := NewMockSSHClient()
				if tt.mockSetup != nil {
					tt.mockSetup(mock)
				}
				r = &FileResource{
					sshClientFactory: MockSSHClientFactory(mock),
				}
			}

			err := r.syncLocalFromRemote(context.Background(), tt.data)

			if tt.wantErr {
				if err == nil {
					t.Error("syncLocalFromRemote() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("syncLocalFromRemote() unexpected error: %v", err)
				return
			}

			if tt.checkFile {
				// Verify the local file was created
				content, err := os.ReadFile(sourcePath)
				if err != nil {
					t.Errorf("failed to read created local file: %v", err)
					return
				}
				if len(content) == 0 {
					t.Error("local file is empty")
				}
			}
		})
	}
}

// TestFileResource_Read_WithCheckRemoteOnPlan tests Read with check_remote_on_plan enabled.
func TestFileResource_Read_WithCheckRemoteOnPlan(t *testing.T) {
	tests := []struct {
		name            string
		mockSetup       func(*MockSSHClient)
		factoryErr      error
		wantWarning     bool
		warningContains string
	}{
		{
			name: "no drift detected",
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/test.txt"] = true
				m.FileHashes["/remote/test.txt"] = "sha256:abc123"
			},
			wantWarning: false,
		},
		{
			name: "drift detected - shows warning",
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/test.txt"] = true
				m.FileHashes["/remote/test.txt"] = "sha256:different"
			},
			wantWarning:     true,
			warningContains: "drift detected",
		},
		{
			name: "remote file missing - shows warning",
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/test.txt"] = false
			},
			wantWarning:     true,
			warningContains: "does not exist",
		},
		{
			name:            "SSH connection error - shows warning",
			factoryErr:      errors.New("connection refused"),
			wantWarning:     true,
			warningContains: "drift check failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sourceFile := filepath.Join(tmpDir, "source.txt")
			if err := os.WriteFile(sourceFile, []byte("test content"), 0644); err != nil {
				t.Fatal(err)
			}

			var r *FileResource
			if tt.factoryErr != nil {
				r = &FileResource{
					sshClientFactory: MockSSHClientFactoryWithError(tt.factoryErr),
				}
			} else {
				mock := NewMockSSHClient()
				if tt.mockSetup != nil {
					tt.mockSetup(mock)
				}
				r = &FileResource{
					sshClientFactory: MockSSHClientFactory(mock),
				}
			}

			data := FileResourceModel{
				Source:            types.StringValue(sourceFile),
				Destination:       types.StringValue("/remote/test.txt"),
				Host:              types.StringValue("192.168.1.100"),
				SSHPort:           types.Int64Value(22),
				SSHUser:           types.StringValue("root"),
				ID:                types.StringValue("192.168.1.100:/remote/test.txt"),
				SourceHash:        types.StringValue("sha256:abc123"),
				CheckRemoteOnPlan: types.BoolValue(true),
			}

			var schemaResp resource.SchemaResponse
			r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

			stateVal := buildTerraformValue(t, schemaResp.Schema, data)
			req := resource.ReadRequest{
				State: tfsdk.State{
					Schema: schemaResp.Schema,
					Raw:    stateVal,
				},
			}

			resp := &resource.ReadResponse{
				State: tfsdk.State{
					Schema: schemaResp.Schema,
					Raw:    stateVal,
				},
			}

			r.Read(context.Background(), req, resp)

			// Check for warnings
			hasWarning := false
			warningText := ""
			for _, diag := range resp.Diagnostics {
				if diag.Severity().String() == "Warning" {
					hasWarning = true
					warningText = diag.Detail()
					break
				}
			}

			if tt.wantWarning && !hasWarning {
				t.Error("Read() expected warning, got none")
			}
			if !tt.wantWarning && hasWarning {
				t.Errorf("Read() unexpected warning: %s", warningText)
			}
			if tt.wantWarning && tt.warningContains != "" {
				found := false
				for _, diag := range resp.Diagnostics {
					if diag.Severity().String() == "Warning" {
						if strings.Contains(strings.ToLower(diag.Summary()), tt.warningContains) ||
							strings.Contains(strings.ToLower(diag.Detail()), tt.warningContains) {
							found = true
							break
						}
					}
				}
				if !found {
					t.Errorf("Read() warning should contain %q, got: %s", tt.warningContains, warningText)
				}
			}
		})
	}
}

// TestFileResource_Read_WithImportSyncsLocal tests Read with import_syncs_local enabled.
func TestFileResource_Read_WithImportSyncsLocal(t *testing.T) {
	tests := []struct {
		name          string
		setupLocal    bool // whether to create local file first
		mockSetup     func(*MockSSHClient)
		factoryErr    error
		wantErr       bool
		wantLocalFile bool // whether local file should exist after
	}{
		{
			name:       "syncs when local file missing and state hash empty",
			setupLocal: false,
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/test.txt"] = true
				m.FileContents["/remote/test.txt"] = []byte("remote content")
				m.FileHashes["/remote/test.txt"] = "sha256:remotehash"
			},
			wantErr:       false,
			wantLocalFile: true,
		},
		{
			name:       "skips sync when local file exists",
			setupLocal: true,
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/test.txt"] = true
				m.FileContents["/remote/test.txt"] = []byte("remote content")
			},
			wantErr:       false,
			wantLocalFile: true,
		},
		{
			name:       "error when remote sync fails",
			setupLocal: false,
			mockSetup: func(m *MockSSHClient) {
				m.ExistingFiles["/remote/test.txt"] = false // Remote doesn't exist
			},
			wantErr:       true,
			wantLocalFile: false,
		},
		{
			name:       "error when SSH connection fails",
			setupLocal: false,
			factoryErr: errors.New("connection refused"),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sourceFile := filepath.Join(tmpDir, "source.txt")

			if tt.setupLocal {
				if err := os.WriteFile(sourceFile, []byte("local content"), 0644); err != nil {
					t.Fatal(err)
				}
			}

			var r *FileResource
			if tt.factoryErr != nil {
				r = &FileResource{
					sshClientFactory: MockSSHClientFactoryWithError(tt.factoryErr),
				}
			} else {
				mock := NewMockSSHClient()
				if tt.mockSetup != nil {
					tt.mockSetup(mock)
				}
				r = &FileResource{
					sshClientFactory: MockSSHClientFactory(mock),
				}
			}

			data := FileResourceModel{
				Source:           types.StringValue(sourceFile),
				Destination:      types.StringValue("/remote/test.txt"),
				Host:             types.StringValue("192.168.1.100"),
				SSHPort:          types.Int64Value(22),
				SSHUser:          types.StringValue("root"),
				ID:               types.StringValue("192.168.1.100:/remote/test.txt"),
				SourceHash:       types.StringNull(), // Empty hash indicates fresh import
				ImportSyncsLocal: types.BoolValue(true),
			}

			var schemaResp resource.SchemaResponse
			r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

			stateVal := buildTerraformValue(t, schemaResp.Schema, data)
			req := resource.ReadRequest{
				State: tfsdk.State{
					Schema: schemaResp.Schema,
					Raw:    stateVal,
				},
			}

			resp := &resource.ReadResponse{
				State: tfsdk.State{
					Schema: schemaResp.Schema,
					Raw:    stateVal,
				},
			}

			r.Read(context.Background(), req, resp)

			if tt.wantErr {
				if !resp.Diagnostics.HasError() {
					t.Error("Read() expected error, got none")
				}
				return
			}

			if resp.Diagnostics.HasError() {
				t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
				return
			}

			// Check if local file exists as expected
			_, err := os.Stat(sourceFile)
			fileExists := err == nil

			if tt.wantLocalFile && !fileExists {
				t.Error("Read() expected local file to be created, but it doesn't exist")
			}
		})
	}
}

// TestFileResource_Read_SourceNotSet tests Read when source is not set (after import).
func TestFileResource_Read_SourceNotSet(t *testing.T) {
	r := &FileResource{}

	data := FileResourceModel{
		Source:      types.StringNull(), // Not set after import
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	stateVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.ReadRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	r.Read(context.Background(), req, resp)

	// Should not error - just preserve state
	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
	}
}

// TestFileResource_Read_EmptySourceString tests Read with empty source string.
func TestFileResource_Read_EmptySourceString(t *testing.T) {
	r := &FileResource{}

	data := FileResourceModel{
		Source:      types.StringValue(""), // Empty string
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	stateVal := buildTerraformValue(t, schemaResp.Schema, data)
	req := resource.ReadRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	r.Read(context.Background(), req, resp)

	// Should not error - just preserve state
	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
	}
}

// TestFileResource_Update_NoDrift tests update when remote file has not drifted.
func TestFileResource_Update_NoDrift(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("updated content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockSSHClient()
	// Remote hash matches state hash - no drift
	mock.FileHashes["/remote/test.txt"] = "sha256:originalhash"
	mock.ExistingFiles["/remote/test.txt"] = true
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
		SourceHash:  types.StringValue("sha256:originalhash"),
		Mode:        types.StringValue("0644"),
		Owner:       types.StringValue("root"),
		Group:       types.StringValue("root"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	stateVal := buildTerraformValue(t, schemaResp.Schema, data)

	req := resource.UpdateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.UpdateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Update() unexpected error: %v", resp.Diagnostics)
	}

	if mock.UploadCalls != 1 {
		t.Errorf("expected 1 upload call, got %d", mock.UploadCalls)
	}
}

// TestFileResource_Update_FileNotFoundAfterImport tests update when remote file doesn't exist (e.g., first apply after import).
func TestFileResource_Update_FileNotFoundAfterImport(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockSSHClient()
	// File doesn't exist on remote - simulating first upload after import
	mock.ExistingFiles["/remote/test.txt"] = false
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
		SourceHash:  types.StringValue("sha256:abc123"),
		Mode:        types.StringValue("0644"),
		Owner:       types.StringValue("root"),
		Group:       types.StringValue("root"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	stateVal := buildTerraformValue(t, schemaResp.Schema, data)

	req := resource.UpdateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.UpdateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Update() unexpected error: %v", resp.Diagnostics)
	}

	// Should still upload even though file didn't exist
	if mock.UploadCalls != 1 {
		t.Errorf("expected 1 upload call, got %d", mock.UploadCalls)
	}
}

// TestFileResource_Update_FileExistsCheckError tests update when FileExists returns an error.
func TestFileResource_Update_FileExistsCheckError(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockSSHClient()
	// File exists but GetFileHash fails, and FileExists also fails
	mock.GetHashError = errors.New("hash failed")
	mock.ExistsError = errors.New("permission denied")
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
		SourceHash:  types.StringValue("sha256:abc123"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	stateVal := buildTerraformValue(t, schemaResp.Schema, data)

	req := resource.UpdateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.UpdateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Update(context.Background(), req, resp)

	// Should error because we can't verify remote state
	if !resp.Diagnostics.HasError() {
		t.Error("Update() expected error for file exists check failure")
	}
}

// TestFileResource_Update_FileExistsButCantRead tests update when file exists but can't be read.
func TestFileResource_Update_FileExistsButCantRead(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockSSHClient()
	// GetFileHash fails but file exists
	mock.GetHashError = errors.New("permission denied reading file")
	mock.ExistingFiles["/remote/test.txt"] = true
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
		SourceHash:  types.StringValue("sha256:abc123"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	stateVal := buildTerraformValue(t, schemaResp.Schema, data)

	req := resource.UpdateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.UpdateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Update(context.Background(), req, resp)

	// Should error because we can read the file but can't verify it
	if !resp.Diagnostics.HasError() {
		t.Error("Update() expected error for permission denied on read")
	}
}

// TestFileResource_Update_SetAttributesError tests update when SetFileAttributes fails.
func TestFileResource_Update_SetAttributesError(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockSSHClient()
	mock.FileHashes["/remote/test.txt"] = "sha256:abc123"
	mock.ExistingFiles["/remote/test.txt"] = true
	mock.SetAttributeError = errors.New("chown failed")
	r := &FileResource{
		sshClientFactory: MockSSHClientFactory(mock),
	}

	data := FileResourceModel{
		Source:      types.StringValue(sourceFile),
		Destination: types.StringValue("/remote/test.txt"),
		Host:        types.StringValue("192.168.1.100"),
		SSHPort:     types.Int64Value(22),
		SSHUser:     types.StringValue("root"),
		ID:          types.StringValue("192.168.1.100:/remote/test.txt"),
		SourceHash:  types.StringValue("sha256:abc123"),
		Owner:       types.StringValue("root"),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	planVal := buildTerraformValue(t, schemaResp.Schema, data)
	stateVal := buildTerraformValue(t, schemaResp.Schema, data)

	req := resource.UpdateRequest{
		Plan: tfsdk.Plan{
			Schema: schemaResp.Schema,
			Raw:    planVal,
		},
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    stateVal,
		},
	}

	resp := &resource.UpdateResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	r.Update(context.Background(), req, resp)

	// Should error because we can't set attributes
	if !resp.Diagnostics.HasError() {
		t.Error("Update() expected error for set attributes failure")
	}
}

// TestSourceSizePlanModifier tests the sourceSizePlanModifier.
func TestSourceSizePlanModifier(t *testing.T) {
	t.Run("description", func(t *testing.T) {
		m := sourceSizePlanModifier{}
		desc := m.Description(context.Background())
		if desc == "" {
			t.Error("Description should not be empty")
		}
		mdDesc := m.MarkdownDescription(context.Background())
		if mdDesc == "" {
			t.Error("MarkdownDescription should not be empty")
		}
	})

	t.Run("computes size for existing file", func(t *testing.T) {
		// Create a temp file with known content.
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		content := []byte("test content 12345")
		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		m := sourceSizePlanModifier{}

		planVal := tftypes.NewValue(tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"source": tftypes.String,
				"size":   tftypes.Number,
			},
		}, map[string]tftypes.Value{
			"source": tftypes.NewValue(tftypes.String, testFile),
			"size":   tftypes.NewValue(tftypes.Number, nil),
		})

		planSchema := schema.Schema{
			Attributes: map[string]schema.Attribute{
				"source": schema.StringAttribute{},
				"size":   schema.Int64Attribute{Computed: true},
			},
		}

		plan := tfsdk.Plan{
			Raw:    planVal,
			Schema: planSchema,
		}

		req := planmodifier.Int64Request{
			Plan:      plan,
			PlanValue: types.Int64Null(),
		}
		resp := &planmodifier.Int64Response{}

		m.PlanModifyInt64(context.Background(), req, resp)

		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error: %v", resp.Diagnostics)
		}

		if resp.PlanValue.IsNull() || resp.PlanValue.IsUnknown() {
			t.Error("expected a computed size value")
		}

		if resp.PlanValue.ValueInt64() != int64(len(content)) {
			t.Errorf("expected size %d, got %d", len(content), resp.PlanValue.ValueInt64())
		}
	})

	t.Run("returns unknown for missing file", func(t *testing.T) {
		m := sourceSizePlanModifier{}

		planVal := tftypes.NewValue(tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"source": tftypes.String,
				"size":   tftypes.Number,
			},
		}, map[string]tftypes.Value{
			"source": tftypes.NewValue(tftypes.String, "/nonexistent/file.txt"),
			"size":   tftypes.NewValue(tftypes.Number, nil),
		})

		planSchema := schema.Schema{
			Attributes: map[string]schema.Attribute{
				"source": schema.StringAttribute{},
				"size":   schema.Int64Attribute{Computed: true},
			},
		}

		plan := tfsdk.Plan{
			Raw:    planVal,
			Schema: planSchema,
		}

		req := planmodifier.Int64Request{
			Plan:      plan,
			PlanValue: types.Int64Null(),
		}
		resp := &planmodifier.Int64Response{}

		m.PlanModifyInt64(context.Background(), req, resp)

		if !resp.PlanValue.IsUnknown() {
			t.Error("expected unknown value for missing file")
		}
	})

	t.Run("skips on destroy", func(t *testing.T) {
		m := sourceSizePlanModifier{}

		req := planmodifier.Int64Request{
			Plan: tfsdk.Plan{Raw: tftypes.NewValue(tftypes.Object{}, nil)},
		}
		resp := &planmodifier.Int64Response{
			PlanValue: types.Int64Value(999),
		}

		m.PlanModifyInt64(context.Background(), req, resp)

		if resp.PlanValue.ValueInt64() != 999 {
			t.Error("should not modify value on destroy")
		}
	})
}
