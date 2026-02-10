package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	InsecureIgnoreHostKey types.Bool   `tfsdk:"insecure_ignore_host_key"`
	KnownHostsFile        types.String `tfsdk:"known_hosts_file"`
	StrictHostKeyChecking types.String `tfsdk:"strict_host_key_checking"`

	// Optional - file attributes.
	Owner types.String `tfsdk:"owner"`
	Group types.String `tfsdk:"group"`
	Mode  types.String `tfsdk:"mode"`

	// Optional - sync behavior.
	CheckRemoteOnPlan types.Bool `tfsdk:"check_remote_on_plan"`
	ImportSyncsLocal  types.Bool `tfsdk:"import_syncs_local"`
	HostAgnosticID    types.Bool `tfsdk:"host_agnostic_id"`

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
  - If ` + "`check_remote_on_plan = true`" + `, also connects to remote to detect drift early.
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
    - terraform import with import_syncs_local=true  # Accept remote as source of truth
    - terraform apply -replace=filesync_file.config  # Force overwrite
` + "```" + `

### Early Drift Detection (check_remote_on_plan)

Set ` + "`check_remote_on_plan = true`" + ` to detect drift during ` + "`terraform plan`" + `:

` + "```hcl" + `
resource "filesync_file" "config" {
  source      = "./config.json"
  destination = "/app/config.json"
  host        = "192.168.1.100"

  check_remote_on_plan = true  # Warn about drift during plan
}
` + "```" + `

This adds latency to planning (requires SSH connection) but provides early warning.

## Importing Existing Remote Files

Use ` + "`import_syncs_local = true`" + ` to download remote file content to local path during import:

` + "```hcl" + `
resource "filesync_file" "workflow" {
  source      = "./workflows/my-workflow.json"
  destination = "/app/workflow.json"
  host        = "192.168.1.100"

  import_syncs_local = true  # Download remote to local on import
}
` + "```" + `

Then import:
` + "```bash" + `
terraform import filesync_file.workflow "192.168.1.100:/app/workflow.json"
` + "```" + `

The remote file content will be written to ` + "`./workflows/my-workflow.json`" + `.

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
			"known_hosts_file": schema.StringAttribute{
				MarkdownDescription: "Path to a custom known_hosts file for SSH host key verification. Supports ~ expansion. If not set, uses the default ~/.ssh/known_hosts. Ignored if insecure_ignore_host_key is true.",
				Optional:            true,
			},
			"strict_host_key_checking": schema.StringAttribute{
				MarkdownDescription: "SSH host key checking mode (like OpenSSH StrictHostKeyChecking). Valid values: `yes` (default) - strict checking, fail if unknown or mismatched; `no` - skip all verification (insecure); `accept-new` - accept and save new keys, fail on mismatch. Takes precedence over insecure_ignore_host_key if both are set.",
				Optional:            true,
			},

			// Optional - file attributes.
			"owner": schema.StringAttribute{
				MarkdownDescription: "File owner on remote. If not set, no ownership change is made (file is owned by the SSH user). Set explicitly to change ownership (requires appropriate permissions).",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				Validators: []validator.String{
					UnixOwner(),
				},
			},
			"group": schema.StringAttribute{
				MarkdownDescription: "File group on remote. If not set, no group change is made. Set explicitly to change group (requires appropriate permissions).",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
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

			// Optional - sync behavior.
			"check_remote_on_plan": schema.BoolAttribute{
				MarkdownDescription: "If true, connects to the remote host during plan to detect drift. " +
					"This adds latency to planning but provides early warning if remote files were modified outside Terraform. " +
					"When drift is detected, a warning is shown in the plan output. Defaults to false.",
				Optional: true,
			},
			"import_syncs_local": schema.BoolAttribute{
				MarkdownDescription: "If true, when importing an existing remote file, the remote content is written to the local source path. " +
					"This allows you to import a remote file and have the local file created/updated to match. " +
					"The source attribute must still be set in the config to specify where to write the file. Defaults to false.",
				Optional: true,
			},
			"host_agnostic_id": schema.BoolAttribute{
				MarkdownDescription: "If true, the resource ID uses only the destination path (not host:destination). " +
					"This allows the host to change (e.g., switching between network paths to the same machine) " +
					"without causing resource identity conflicts. Defaults to false for backwards compatibility.",
				Optional: true,
			},

			// Computed.
			"id": schema.StringAttribute{
				MarkdownDescription: "Resource identifier. Format depends on host_agnostic_id: " +
					"when false (default), ID is `host:destination`; when true, ID is just `destination`.",
				Computed: true,
				PlanModifiers: []planmodifier.String{
					idPlanModifier{},
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
	data.ID = types.StringValue(computeResourceID(data))
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

	// Check if this is a post-import situation where we need to sync local from remote.
	// Conditions:
	// 1. import_syncs_local is true
	// 2. source_hash is empty/null (indicates fresh import or never synced)
	// 3. Local file doesn't exist OR differs from what we expect
	localFileExists := true
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		localFileExists = false
	}

	shouldSyncFromRemote := !data.ImportSyncsLocal.IsNull() &&
		data.ImportSyncsLocal.ValueBool() &&
		(data.SourceHash.IsNull() || data.SourceHash.ValueString() == "") &&
		!localFileExists

	if shouldSyncFromRemote {
		tflog.Info(ctx, "Post-import sync: downloading remote file to local source path")
		if err := r.syncLocalFromRemote(ctx, &data); err != nil {
			resp.Diagnostics.AddError(
				"Failed to sync local file from remote",
				fmt.Sprintf("import_syncs_local is enabled but sync failed: %v", err),
			)
			return
		}

		// After syncing, compute the hash of the now-local file and update state.
		hash, size, err := hashFile(sourcePath)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to compute hash after sync",
				fmt.Sprintf("Could not hash synced file %s: %v", sourcePath, err),
			)
			return
		}

		data.SourceHash = types.StringValue(hash)
		data.Size = types.Int64Value(size)

		tflog.Info(ctx, "Successfully synced local file and updated state", map[string]interface{}{
			"source": sourcePath,
			"hash":   hash,
			"size":   size,
		})

		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}

	if !localFileExists {
		tflog.Info(ctx, "Source file no longer exists, removing resource from state", map[string]interface{}{
			"source": sourcePath,
		})
		// Source file was deleted - remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	// Check for remote drift if check_remote_on_plan is enabled.
	hasDrift, remoteHash, err := r.checkRemoteDrift(ctx, &data)
	if err != nil {
		// Add warning but don't fail - drift check is informational.
		resp.Diagnostics.AddWarning(
			"Remote drift check failed",
			fmt.Sprintf("Could not check remote file for drift: %v\n\n"+
				"This may indicate connectivity issues. The apply will still check for drift.", err),
		)
	} else if hasDrift {
		if remoteHash == "" {
			resp.Diagnostics.AddWarning(
				"Remote file missing",
				fmt.Sprintf("Remote file %s does not exist but is expected.\n\n"+
					"The file may have been deleted outside of Terraform.\n"+
					"Run 'terraform apply' to recreate the file.",
					data.Destination.ValueString()),
			)
		} else {
			resp.Diagnostics.AddWarning(
				"Remote file drift detected",
				fmt.Sprintf("Remote file %s has been modified outside of Terraform.\n\n"+
					"  Expected (from state): %s\n"+
					"  Found (on remote):     %s\n\n"+
					"To resolve:\n"+
					"  - Run 'terraform apply' to overwrite remote with local (will fail with drift error)\n"+
					"  - Run 'terraform apply -replace=%s' to force overwrite\n"+
					"  - Run 'terraform import' with import_syncs_local=true to accept remote changes",
					data.Destination.ValueString(),
					data.SourceHash.ValueString(),
					remoteHash,
					fmt.Sprintf("filesync_file.%s", data.ID.ValueString())),
			)
		}
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
	data.ID = types.StringValue(computeResourceID(data))
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
	// If import_syncs_local=true in the config, the remote file content will be
	// written to the source path during the first Read after import.
	//
	// Then run `terraform apply` to sync state with the config.

	id := req.ID
	tflog.Info(ctx, "Importing file resource", map[string]interface{}{
		"import_id": id,
	})

	// Parse the import ID.
	// Two formats supported:
	//   - "host:destination" (default, e.g. "192.168.1.100:/etc/myapp/config.json")
	//   - "/destination" (host_agnostic_id mode, e.g. "/etc/myapp/config.json")
	//
	// If the ID starts with "/", it's a host-agnostic import (destination only).
	// Otherwise, split on the first ":" to get host and destination.
	if strings.HasPrefix(id, "/") {
		// Host-agnostic mode: ID is just the absolute destination path.
		// The host must be provided in the resource config.
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("destination"), id)...)
	} else {
		colonIdx := strings.Index(id, ":")
		if colonIdx == -1 || colonIdx == 0 || colonIdx == len(id)-1 {
			resp.Diagnostics.AddError(
				"Invalid Import ID",
				fmt.Sprintf(
					"Import ID must be either 'host:destination' (e.g., '192.168.1.100:/etc/myapp/config.json') "+
						"or an absolute path '/destination' for host_agnostic_id mode.\n"+
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
}

// syncLocalFromRemote downloads the remote file content to the local source path.
// This is called during Read when import_syncs_local=true and the local file
// doesn't exist or differs from remote.
func (r *FileResource) syncLocalFromRemote(ctx context.Context, data *FileResourceModel) error {
	sourcePath := data.Source.ValueString()
	if sourcePath == "" {
		return fmt.Errorf("source path is not set - add 'source' attribute to your config")
	}

	tflog.Info(ctx, "Syncing local file from remote (import_syncs_local=true)", map[string]interface{}{
		"source":      sourcePath,
		"destination": data.Destination.ValueString(),
	})

	// Create SSH client.
	client, err := r.createSSHClient(data)
	if err != nil {
		return fmt.Errorf("failed to create SSH connection: %w", err)
	}
	defer r.releaseSSHClient(data, client)

	// Check if remote file exists.
	exists, err := client.FileExists(ctx, data.Destination.ValueString())
	if err != nil {
		return fmt.Errorf("failed to check if remote file exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("remote file %s does not exist", data.Destination.ValueString())
	}

	// Read remote file content.
	content, err := client.ReadFileContent(ctx, data.Destination.ValueString(), 0) // 0 = no limit
	if err != nil {
		return fmt.Errorf("failed to read remote file content: %w", err)
	}

	// Create parent directories if needed.
	dir := filepath.Dir(sourcePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create parent directory %s: %w", dir, err)
	}

	// Write content to local file atomically (write to temp, then rename).
	tmpPath := sourcePath + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write temporary file %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, sourcePath); err != nil {
		os.Remove(tmpPath) // Clean up temp file on error.
		return fmt.Errorf("failed to rename temporary file to %s: %w", sourcePath, err)
	}

	tflog.Info(ctx, "Successfully synced local file from remote", map[string]interface{}{
		"source": sourcePath,
		"size":   len(content),
	})

	return nil
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
	client, err := factory(config)
	if err != nil {
		// Provide detailed error message for debugging SSH connection issues.
		return nil, fmt.Errorf("%w (host=%s, port=%d, user=%s, insecure_ignore_host_key=%v, has_key=%v, has_password=%v)",
			err,
			config.Host,
			config.Port,
			config.User,
			config.InsecureIgnoreHostKey,
			config.KeyPath != "" || config.PrivateKey != "",
			config.Password != "",
		)
	}
	return client, nil
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

// computeResourceID returns the resource ID based on the host_agnostic_id flag.
// When host_agnostic_id is true, returns just the destination path.
// When false (default), returns host:destination for backwards compatibility.
func computeResourceID(data FileResourceModel) string {
	if !data.HostAgnosticID.IsNull() && data.HostAgnosticID.ValueBool() {
		return data.Destination.ValueString()
	}
	return fmt.Sprintf("%s:%s", data.Host.ValueString(), data.Destination.ValueString())
}

// idPlanModifier computes the resource ID during planning.
// This ensures the planned ID matches what Create/Update will produce,
// avoiding "inconsistent result after apply" errors when host changes.
type idPlanModifier struct{}

func (m idPlanModifier) Description(_ context.Context) string {
	return "Computes resource ID from host and destination, respecting host_agnostic_id flag."
}

func (m idPlanModifier) MarkdownDescription(_ context.Context) string {
	return "Computes resource ID from host and destination, respecting host_agnostic_id flag."
}

func (m idPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If resource is being destroyed, don't compute ID.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Get host and destination from the plan.
	var host types.String
	var destination types.String
	var hostAgnosticID types.Bool

	diags := req.Plan.GetAttribute(ctx, path.Root("host"), &host)
	resp.Diagnostics.Append(diags...)
	diags = req.Plan.GetAttribute(ctx, path.Root("destination"), &destination)
	resp.Diagnostics.Append(diags...)
	diags = req.Plan.GetAttribute(ctx, path.Root("host_agnostic_id"), &hostAgnosticID)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	// If either value is unknown, we can't compute the ID yet.
	if host.IsUnknown() || destination.IsUnknown() {
		resp.PlanValue = types.StringUnknown()
		return
	}

	// Compute the ID based on the flag.
	if !hostAgnosticID.IsNull() && hostAgnosticID.ValueBool() {
		resp.PlanValue = types.StringValue(destination.ValueString())
	} else {
		resp.PlanValue = types.StringValue(fmt.Sprintf("%s:%s", host.ValueString(), destination.ValueString()))
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
		// File doesn't exist or can't be read.
		// Check if import_syncs_local is enabled - if so, and state hash is empty,
		// this indicates a post-import scenario where Read will sync the file.
		var importSyncsLocal types.Bool
		diags := req.Plan.GetAttribute(ctx, path.Root("import_syncs_local"), &importSyncsLocal)
		if !diags.HasError() && !importSyncsLocal.IsNull() && importSyncsLocal.ValueBool() {
			// Check if state hash is empty (indicates fresh import).
			if req.StateValue.IsNull() || req.StateValue.ValueString() == "" {
				// Use empty string to match state - Read will sync the file from remote.
				tflog.Debug(ctx, "import_syncs_local enabled with empty state hash, will sync from remote during Read")
				resp.PlanValue = types.StringValue("")
				return
			}
		}

		// Otherwise, use unknown value to indicate we can't compute it.
		// This will let Create/Update handle the error.
		resp.PlanValue = types.StringUnknown()
		return
	}

	// Set the planned value to the current local file hash.
	// If this differs from state, Terraform will trigger an update.
	resp.PlanValue = types.StringValue(hash)
}

// remoteDriftChecker is used to check for remote drift during the Read phase.
// This is called when check_remote_on_plan is true.
// Note: We can't check during plan modifiers because they don't have access to
// provider config (SSH credentials). Instead, we check during Read which runs
// as part of refresh during plan.
func (r *FileResource) checkRemoteDrift(ctx context.Context, data *FileResourceModel) (hasDrift bool, remoteHash string, err error) {
	// Skip if check_remote_on_plan is not enabled.
	if data.CheckRemoteOnPlan.IsNull() || !data.CheckRemoteOnPlan.ValueBool() {
		return false, "", nil
	}

	// Skip if we don't have state hash to compare against.
	if data.SourceHash.IsNull() || data.SourceHash.IsUnknown() {
		return false, "", nil
	}

	tflog.Debug(ctx, "Checking remote for drift (check_remote_on_plan=true)")

	// Create SSH client.
	client, err := r.createSSHClient(data)
	if err != nil {
		return false, "", fmt.Errorf("failed to create SSH connection for drift check: %w", err)
	}
	defer r.releaseSSHClient(data, client)

	// Check if file exists.
	exists, err := client.FileExists(ctx, data.Destination.ValueString())
	if err != nil {
		return false, "", fmt.Errorf("failed to check if remote file exists: %w", err)
	}
	if !exists {
		// File doesn't exist on remote - this is drift (file was deleted).
		return true, "", nil
	}

	// Get remote file hash.
	remoteHash, err = client.GetFileHash(ctx, data.Destination.ValueString())
	if err != nil {
		return false, "", fmt.Errorf("failed to get remote file hash: %w", err)
	}

	// Compare with state hash.
	stateHash := data.SourceHash.ValueString()
	if remoteHash != stateHash {
		tflog.Warn(ctx, "Remote drift detected", map[string]interface{}{
			"state_hash":  stateHash,
			"remote_hash": remoteHash,
		})
		return true, remoteHash, nil
	}

	tflog.Debug(ctx, "No remote drift detected")
	return false, remoteHash, nil
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
