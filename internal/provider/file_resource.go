package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/darshan-rambhia/gosftp"
	"github.com/darshan-rambhia/terraform-provider-filesync/internal/diff"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &FileResource{}
var _ resource.ResourceWithImportState = &FileResource{}

func NewFileResource() resource.Resource {
	return &FileResource{
		sshClientFactory: DefaultSSHClientFactory,
	}
}

// SSHClientFactory is a function type that creates SSH clients.
// This allows for dependency injection in tests.
type SSHClientFactory func(config gosftp.Config) (gosftp.ClientInterface, error)

// DefaultSSHClientFactory creates real SSH clients.
var DefaultSSHClientFactory SSHClientFactory = func(config gosftp.Config) (gosftp.ClientInterface, error) {
	return gosftp.NewClient(config)
}

// FileResource defines the resource implementation.
type FileResource struct {
	providerConfig   *FilesyncProviderModel
	sshClientFactory SSHClientFactory
}

// FileResourceModel describes the resource data model.
type FileResourceModel struct {
	// Required.
	Source      types.String `tfsdk:"source"`
	Destination types.String `tfsdk:"destination"`
	Host        types.String `tfsdk:"host"`

	// Optional - connection settings (override provider defaults).
	SSHUser            types.String `tfsdk:"ssh_user"`
	SSHPrivateKey      types.String `tfsdk:"ssh_private_key"`
	SSHKeyPath         types.String `tfsdk:"ssh_key_path"`
	SSHPort            types.Int64  `tfsdk:"ssh_port"`
	SSHPassword        types.String `tfsdk:"ssh_password"`
	SSHCertificate     types.String `tfsdk:"ssh_certificate"`
	SSHCertificatePath types.String `tfsdk:"ssh_certificate_path"`

	// Optional - bastion/jump host settings.
	BastionHost     types.String `tfsdk:"bastion_host"`
	BastionPort     types.Int64  `tfsdk:"bastion_port"`
	BastionUser     types.String `tfsdk:"bastion_user"`
	BastionKey      types.String `tfsdk:"bastion_private_key"`
	BastionKeyPath  types.String `tfsdk:"bastion_key_path"`
	BastionPassword types.String `tfsdk:"bastion_password"`

	// Optional - security settings.
	InsecureIgnoreHostKey types.Bool `tfsdk:"insecure_ignore_host_key"`

	// Optional - file attributes.
	Owner types.String `tfsdk:"owner"`
	Group types.String `tfsdk:"group"`
	Mode  types.String `tfsdk:"mode"`

	// Computed.
	ID         types.String `tfsdk:"id"`
	SourceHash types.String `tfsdk:"source_hash"`
	Size       types.Int64  `tfsdk:"size"`
}

func (r *FileResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (r *FileResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `
Manages a single file on a remote host via SSH/SFTP.

## Behavior

- **Plan**: Compares local file hash against state. Shows change if local file modified.
- **Apply**:
  1. Connects to remote host via SSH
  2. Checks remote file hash against state (drift detection)
  3. If remote was modified externally, fails with error showing diff
  4. If no drift, uploads new file content
  5. Sets ownership and permissions
  6. Updates state with new hash

## Drift Detection

If someone modifies the remote file outside of Terraform, apply will fail:

` + "```" + `
Error: Remote file drift detected

  Resource: filesync_file.config
  File: /etc/myapp/app.conf

  Expected (from state): sha256:abc123...
  Found (on remote):     sha256:def456...

  To resolve:
    - terraform refresh   # Accept remote as source of truth
    - terraform apply -replace=filesync_file.config  # Force overwrite
` + "```" + `

## Example Usage

` + "```hcl" + `
resource "filesync_file" "nginx_config" {
  source      = "${path.module}/configs/nginx.conf"
  destination = "/etc/nginx/nginx.conf"
  host        = "192.168.1.100"

  owner = "root"
  group = "root"
  mode  = "0644"

  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/deploy_key"
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			// Required.
			"source": schema.StringAttribute{
				MarkdownDescription: "Path to the local source file. Can be relative or absolute path.",
				Required:            true,
			},
			"destination": schema.StringAttribute{
				MarkdownDescription: "Absolute path on the remote host where the file should be placed.",
				Required:            true,
				Validators: []validator.String{
					AbsolutePath(),
				},
			},
			"host": schema.StringAttribute{
				MarkdownDescription: "Remote host address (IP or hostname).",
				Required:            true,
			},

			// Optional - connection.
			"ssh_user": schema.StringAttribute{
				MarkdownDescription: "SSH user. Overrides provider default.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("root"),
			},
			"ssh_private_key": schema.StringAttribute{
				MarkdownDescription: "SSH private key content. Mutually exclusive with ssh_key_path.",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("ssh_key_path")),
				},
			},
			"ssh_key_path": schema.StringAttribute{
				MarkdownDescription: "Path to SSH private key file. Mutually exclusive with ssh_private_key.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("ssh_private_key")),
				},
			},
			"ssh_port": schema.Int64Attribute{
				MarkdownDescription: "SSH port. Defaults to 22.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(22),
			},
			"ssh_password": schema.StringAttribute{
				MarkdownDescription: "SSH password for password authentication. Overrides provider default.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_certificate": schema.StringAttribute{
				MarkdownDescription: "SSH certificate content for certificate authentication. Used with ssh_private_key or ssh_key_path. Overrides provider default.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_certificate_path": schema.StringAttribute{
				MarkdownDescription: "Path to SSH certificate file for certificate authentication. Used with ssh_private_key or ssh_key_path. Overrides provider default.",
				Optional:            true,
			},

			// Optional - bastion/jump host.
			"bastion_host": schema.StringAttribute{
				MarkdownDescription: "Bastion/jump host address for multi-hop SSH connections.",
				Optional:            true,
			},
			"bastion_port": schema.Int64Attribute{
				MarkdownDescription: "Bastion host SSH port. Defaults to 22.",
				Optional:            true,
			},
			"bastion_user": schema.StringAttribute{
				MarkdownDescription: "SSH user for bastion host. Falls back to ssh_user if not set.",
				Optional:            true,
			},
			"bastion_private_key": schema.StringAttribute{
				MarkdownDescription: "SSH private key content for bastion host (sensitive). Falls back to ssh_private_key if not set.",
				Optional:            true,
				Sensitive:           true,
			},
			"bastion_key_path": schema.StringAttribute{
				MarkdownDescription: "Path to SSH private key file for bastion host. Falls back to ssh_key_path if not set.",
				Optional:            true,
			},
			"bastion_password": schema.StringAttribute{
				MarkdownDescription: "SSH password for bastion host (sensitive).",
				Optional:            true,
				Sensitive:           true,
			},

			// Optional - security settings.
			"insecure_ignore_host_key": schema.BoolAttribute{
				MarkdownDescription: "Skip SSH host key verification. WARNING: This is insecure and should only be used for testing or in trusted environments. Defaults to false.",
				Optional:            true,
			},

			// Optional - file attributes.
			"owner": schema.StringAttribute{
				MarkdownDescription: "File owner on remote. Defaults to the SSH user.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("root"),
				Validators: []validator.String{
					UnixOwner(),
				},
			},
			"group": schema.StringAttribute{
				MarkdownDescription: "File group on remote. Defaults to the SSH user's primary group.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("root"),
				Validators: []validator.String{
					UnixGroup(),
				},
			},
			"mode": schema.StringAttribute{
				MarkdownDescription: "File permissions in octal notation (e.g., '0644' for rw-r--r--). Must be 3-4 digits. Defaults to '0644'.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("0644"),
				Validators: []validator.String{
					OctalMode(),
				},
			},

			// Computed.
			"id": schema.StringAttribute{
				MarkdownDescription: "Resource identifier (host:destination).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"source_hash": schema.StringAttribute{
				MarkdownDescription: "SHA256 hash of the source file in format `sha256:<hex>`. Updated when local file changes.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					sourceHashPlanModifier{},
				},
			},
			"size": schema.Int64Attribute{
				MarkdownDescription: "Size of the file in bytes.",
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					sourceSizePlanModifier{},
				},
			},
		},
	}
}

func (r *FileResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(*FilesyncProviderModel)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *FilesyncProviderModel, got: %T", req.ProviderData),
		)
		return
	}

	r.providerConfig = config
}

func (r *FileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data FileResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "host", data.Host.ValueString())
	ctx = tflog.SetField(ctx, "source", data.Source.ValueString())
	ctx = tflog.SetField(ctx, "destination", data.Destination.ValueString())

	tflog.Info(ctx, "Creating file resource")

	// Calculate source file hash.
	hash, size, err := hashFile(data.Source.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read source file", err.Error())
		return
	}
	tflog.Debug(ctx, "Computed source file hash", map[string]interface{}{
		"hash": hash,
		"size": size,
	})

	// Create SSH client.
	tflog.Debug(ctx, "Establishing SSH connection")
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer r.releaseSSHClient(&data, client)
	tflog.Debug(ctx, "SSH connection established")

	// Upload file.
	tflog.Debug(ctx, "Uploading file")
	if err := client.UploadFile(ctx, data.Source.ValueString(), data.Destination.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to upload file", err.Error())
		return
	}
	tflog.Debug(ctx, "File uploaded successfully")

	// Set ownership and permissions.
	tflog.Debug(ctx, "Setting file attributes", map[string]interface{}{
		"owner": data.Owner.ValueString(),
		"group": data.Group.ValueString(),
		"mode":  data.Mode.ValueString(),
	})
	if err := client.SetFileAttributes(
		ctx,
		data.Destination.ValueString(),
		data.Owner.ValueString(),
		data.Group.ValueString(),
		data.Mode.ValueString(),
	); err != nil {
		resp.Diagnostics.AddError("Failed to set file attributes", err.Error())
		return
	}

	// Set computed values.
	data.ID = types.StringValue(fmt.Sprintf("%s:%s", data.Host.ValueString(), data.Destination.ValueString()))
	data.SourceHash = types.StringValue(hash)
	data.Size = types.Int64Value(size)

	tflog.Info(ctx, "File resource created successfully", map[string]interface{}{
		"id":   data.ID.ValueString(),
		"size": size,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *FileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data FileResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "id", data.ID.ValueString())
	tflog.Debug(ctx, "Reading file resource state")

	// Read refreshes state from the resource.
	// IMPORTANT: We do NOT update source_hash here. The source_hash represents
	// what was last successfully synced to the remote, not the current local file.
	// This allows Terraform to detect local file changes during plan.
	//
	// The plan modifier on source_hash computes the current local file hash
	// and triggers an update when it differs from the stored state hash.

	sourcePath := data.Source.ValueString()

	// If source is not set (e.g., after import), don't remove from state.
	// The user needs to update their config to include the source attribute.
	if sourcePath == "" || data.Source.IsNull() || data.Source.IsUnknown() {
		tflog.Debug(ctx, "Source path not set (possibly after import), preserving state")
		// Preserve the current state - source will be set in next apply.
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}

	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		tflog.Info(ctx, "Source file no longer exists, removing resource from state", map[string]interface{}{
			"source": sourcePath,
		})
		// Source file was deleted - remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	tflog.Debug(ctx, "File resource state preserved")
	// State is unchanged - we preserve the existing source_hash.
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *FileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data FileResourceModel
	var state FileResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "host", data.Host.ValueString())
	ctx = tflog.SetField(ctx, "source", data.Source.ValueString())
	ctx = tflog.SetField(ctx, "destination", data.Destination.ValueString())

	tflog.Info(ctx, "Updating file resource")

	// Calculate new source file hash.
	newHash, size, err := hashFile(data.Source.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read source file", err.Error())
		return
	}
	tflog.Debug(ctx, "Computed new source file hash", map[string]interface{}{
		"new_hash":  newHash,
		"old_hash":  state.SourceHash.ValueString(),
		"size":      size,
		"unchanged": newHash == state.SourceHash.ValueString(),
	})

	// Create SSH client.
	tflog.Debug(ctx, "Establishing SSH connection")
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer r.releaseSSHClient(&data, client)
	tflog.Debug(ctx, "SSH connection established")

	// Check for remote drift - compare remote hash with what we expect from state.
	tflog.Debug(ctx, "Checking for remote drift")
	remoteHash, err := client.GetFileHash(ctx, data.Destination.ValueString())
	if err != nil {
		// Check if file doesn't exist (could be first create after import).
		// We need to distinguish between "file not found" and other errors.
		exists, existsErr := client.FileExists(ctx, data.Destination.ValueString())
		if existsErr != nil {
			// Can't even check if file exists - report the connection/permission issue.
			resp.Diagnostics.AddError(
				"Failed to check remote file",
				fmt.Sprintf("Could not verify remote file state at %s: %v", data.Destination.ValueString(), existsErr),
			)
			return
		}
		if exists {
			// File exists but we can't read it - permission issue.
			resp.Diagnostics.AddError(
				"Cannot read remote file",
				fmt.Sprintf("Remote file %s exists but cannot be read (permission denied?): %v", data.Destination.ValueString(), err),
			)
			return
		}
		tflog.Debug(ctx, "Remote file does not exist (first upload after import)")
		// File doesn't exist - this is OK for first create after import, continue with upload.
	} else if remoteHash != state.SourceHash.ValueString() {
		tflog.Warn(ctx, "Remote file drift detected", map[string]interface{}{
			"expected_hash": state.SourceHash.ValueString(),
			"remote_hash":   remoteHash,
		})
		// Drift detected! Try to generate a content diff for better error message
		var diffContent string

		// Read local file content for diff.
		localContent, localErr := os.ReadFile(data.Source.ValueString())
		if localErr == nil {
			// Read remote file content for diff (limit to 100KB).
			remoteContent, remoteErr := client.ReadFileContent(ctx, data.Destination.ValueString(), diff.MaxDiffSize)
			if remoteErr == nil {
				diffContent = diff.GenerateUnifiedDiff(localContent, remoteContent, data.Destination.ValueString())
			}
		}

		errorMsg := diff.FormatDriftError(
			data.ID.ValueString(),
			data.Destination.ValueString(),
			state.SourceHash.ValueString(),
			remoteHash,
			diffContent,
		)

		resp.Diagnostics.AddError("Remote file drift detected", errorMsg)
		return
	} else {
		tflog.Debug(ctx, "No remote drift detected")
	}

	// Upload file.
	tflog.Debug(ctx, "Uploading file")
	if err := client.UploadFile(ctx, data.Source.ValueString(), data.Destination.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to upload file", err.Error())
		return
	}
	tflog.Debug(ctx, "File uploaded successfully")

	// Set ownership and permissions.
	tflog.Debug(ctx, "Setting file attributes", map[string]interface{}{
		"owner": data.Owner.ValueString(),
		"group": data.Group.ValueString(),
		"mode":  data.Mode.ValueString(),
	})
	if err := client.SetFileAttributes(
		ctx,
		data.Destination.ValueString(),
		data.Owner.ValueString(),
		data.Group.ValueString(),
		data.Mode.ValueString(),
	); err != nil {
		resp.Diagnostics.AddError("Failed to set file attributes", err.Error())
		return
	}

	// Update computed values.
	data.ID = types.StringValue(fmt.Sprintf("%s:%s", data.Host.ValueString(), data.Destination.ValueString()))
	data.SourceHash = types.StringValue(newHash)
	data.Size = types.Int64Value(size)

	tflog.Info(ctx, "File resource updated successfully", map[string]interface{}{
		"id":   data.ID.ValueString(),
		"size": size,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *FileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data FileResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "host", data.Host.ValueString())
	ctx = tflog.SetField(ctx, "destination", data.Destination.ValueString())
	ctx = tflog.SetField(ctx, "id", data.ID.ValueString())

	tflog.Info(ctx, "Deleting file resource")

	// Create SSH client.
	tflog.Debug(ctx, "Establishing SSH connection")
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer r.releaseSSHClient(&data, client)
	tflog.Debug(ctx, "SSH connection established")

	// Delete remote file.
	tflog.Debug(ctx, "Deleting remote file")
	if err := client.DeleteFile(ctx, data.Destination.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to delete remote file", err.Error())
		return
	}

	tflog.Info(ctx, "File resource deleted successfully")
}

func (r *FileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import format: "host:destination".
	// Example: "192.168.1.100:/etc/myapp/config.json"
	//
	// After import, the user must update the config to set:.
	// - source (required): path to the local source file
	// - ssh_key_path or ssh_private_key (required): SSH credentials
	//
	// Then run `terraform apply` to sync state with the config.

	id := req.ID
	tflog.Info(ctx, "Importing file resource", map[string]interface{}{
		"import_id": id,
	})

	// Parse the import ID - format is "host:destination".
	// The destination is an absolute path, so we split on the first ":".
	colonIdx := strings.Index(id, ":")
	if colonIdx == -1 || colonIdx == 0 || colonIdx == len(id)-1 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf(
				"Import ID must be in format 'host:destination' (e.g., '192.168.1.100:/etc/myapp/config.json').\n"+
					"Got: %s", id,
			),
		)
		return
	}

	host := id[:colonIdx]
	destination := id[colonIdx+1:]

	// Validate destination is an absolute path.
	if !strings.HasPrefix(destination, "/") {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf(
				"Destination must be an absolute path starting with '/'.\n"+
					"Got: %s", destination,
			),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("host"), host)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("destination"), destination)...)
}

// Helper functions.

// getSSHConfig builds an SSH config from resource data.
func (r *FileResource) getSSHConfig(data *FileResourceModel) gosftp.Config {
	return BuildSSHConfig(data, r.providerConfig)
}

// isPoolingEnabled checks if connection pooling is enabled.
func (r *FileResource) isPoolingEnabled() bool {
	return r.providerConfig != nil &&
		!r.providerConfig.ConnectionPoolEnabled.IsNull() &&
		r.providerConfig.ConnectionPoolEnabled.ValueBool()
}

// createSSHClient creates or retrieves an SSH client (from pool if enabled).
func (r *FileResource) createSSHClient(data *FileResourceModel) (gosftp.ClientInterface, error) {
	config := r.getSSHConfig(data)

	// Use connection pool if enabled.
	if r.isPoolingEnabled() && r.providerConfig != nil && r.providerConfig.pool != nil {
		return r.providerConfig.pool.GetOrCreate(config)
	}

	// Otherwise, create a new connection using the factory.
	factory := r.sshClientFactory
	if factory == nil {
		factory = DefaultSSHClientFactory
	}
	return factory(config)
}

// releaseSSHClient releases a connection back to the pool (if pooling enabled).
// If pooling is disabled, this closes the connection.
func (r *FileResource) releaseSSHClient(data *FileResourceModel, client gosftp.ClientInterface) {
	if r.isPoolingEnabled() && r.providerConfig != nil && r.providerConfig.pool != nil {
		config := r.getSSHConfig(data)
		r.providerConfig.pool.Release(config)
		// Don't close - the pool manages the connection lifecycle.
	} else {
		// Not pooling - close the connection.
		client.Close()
	}
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil)), size, nil
}

// sourceHashPlanModifier computes the source file hash during planning.
// This allows Terraform to detect local file changes and trigger updates.
type sourceHashPlanModifier struct{}

func (m sourceHashPlanModifier) Description(_ context.Context) string {
	return "Computes hash from current local source file to detect changes."
}

func (m sourceHashPlanModifier) MarkdownDescription(_ context.Context) string {
	return "Computes hash from current local source file to detect changes."
}

func (m sourceHashPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If resource is being destroyed, don't compute hash.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Get the source path from the plan.
	var sourcePath types.String
	diags := req.Plan.GetAttribute(ctx, path.Root("source"), &sourcePath)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() || sourcePath.IsUnknown() || sourcePath.IsNull() {
		return
	}

	// Compute hash of the current local file.
	hash, _, err := hashFile(sourcePath.ValueString())
	if err != nil {
		// File doesn't exist or can't be read - let Create/Update handle the error.
		// Use unknown value to indicate we can't compute it.
		resp.PlanValue = types.StringUnknown()
		return
	}

	// Set the planned value to the current local file hash.
	// If this differs from state, Terraform will trigger an update.
	resp.PlanValue = types.StringValue(hash)
}

// sourceSizePlanModifier computes the source file size during planning.
type sourceSizePlanModifier struct{}

func (m sourceSizePlanModifier) Description(_ context.Context) string {
	return "Computes size from current local source file."
}

func (m sourceSizePlanModifier) MarkdownDescription(_ context.Context) string {
	return "Computes size from current local source file."
}

func (m sourceSizePlanModifier) PlanModifyInt64(ctx context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	// If resource is being destroyed, don't compute size.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Get the source path from the plan.
	var sourcePath types.String
	diags := req.Plan.GetAttribute(ctx, path.Root("source"), &sourcePath)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() || sourcePath.IsUnknown() || sourcePath.IsNull() {
		return
	}

	// Get file size.
	info, err := os.Stat(sourcePath.ValueString())
	if err != nil {
		// File doesn't exist or can't be read - let Create/Update handle the error.
		resp.PlanValue = types.Int64Unknown()
		return
	}

	resp.PlanValue = types.Int64Value(info.Size())
}
