package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/darshan-rambhia/terraform-provider-filesync/internal/ssh"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &DirectoryResource{}
var _ resource.ResourceWithImportState = &DirectoryResource{}

func NewDirectoryResource() resource.Resource {
	return &DirectoryResource{
		sshClientFactory: DefaultSSHClientFactory,
	}
}

// DirectoryResource defines the resource implementation.
type DirectoryResource struct {
	providerConfig   *FilesyncProviderModel
	sshClientFactory SSHClientFactory
}

// DirectoryResourceModel describes the resource data model.
type DirectoryResourceModel struct {
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

	// Optional - sync options.
	Exclude types.List `tfsdk:"exclude"`

	// Computed.
	ID         types.String `tfsdk:"id"`
	SourceHash types.String `tfsdk:"source_hash"`
	FileCount  types.Int64  `tfsdk:"file_count"`
	TotalSize  types.Int64  `tfsdk:"total_size"`
	FileHashes types.Map    `tfsdk:"file_hashes"`
}

func (r *DirectoryResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_directory"
}

func (r *DirectoryResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `
Manages synchronization of a directory to a remote host via SSH/SFTP.

This resource syncs all files in a source directory to a destination directory on the remote host.
It tracks individual file hashes and only uploads files that have changed.

## Behavior

- **Plan**: Computes hashes for all local files, compares with state
- **Apply**:
  1. Connects to remote host via SSH
  2. Creates destination directory structure
  3. Uploads only changed files
  4. Sets ownership and permissions on all files
  5. Removes files from remote that no longer exist locally

## Example Usage

` + "```hcl" + `
resource "filesync_directory" "configs" {
  source      = "${path.module}/configs"
  destination = "/etc/myapp"
  host        = "192.168.1.100"

  owner = "root"
  group = "root"
  mode  = "0644"

  exclude = [
    "*.tmp",
    ".git",
    "*.bak"
  ]
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			// Required.
			"source": schema.StringAttribute{
				MarkdownDescription: "Path to the local source directory.",
				Required:            true,
			},
			"destination": schema.StringAttribute{
				MarkdownDescription: "Absolute path on the remote host where files should be placed.",
				Required:            true,
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
			},
			"ssh_key_path": schema.StringAttribute{
				MarkdownDescription: "Path to SSH private key file. Mutually exclusive with ssh_private_key.",
				Optional:            true,
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
				MarkdownDescription: "Bastion/jump host address for multi-hop SSH connections. Overrides provider default.",
				Optional:            true,
			},
			"bastion_port": schema.Int64Attribute{
				MarkdownDescription: "Bastion host SSH port. Defaults to 22. Overrides provider default.",
				Optional:            true,
			},
			"bastion_user": schema.StringAttribute{
				MarkdownDescription: "SSH user for bastion host. Falls back to ssh_user if not set. Overrides provider default.",
				Optional:            true,
			},
			"bastion_private_key": schema.StringAttribute{
				MarkdownDescription: "SSH private key content for bastion host (sensitive). Falls back to ssh_private_key if not set. Overrides provider default.",
				Optional:            true,
				Sensitive:           true,
			},
			"bastion_key_path": schema.StringAttribute{
				MarkdownDescription: "Path to SSH private key file for bastion host. Falls back to ssh_key_path if not set. Overrides provider default.",
				Optional:            true,
			},
			"bastion_password": schema.StringAttribute{
				MarkdownDescription: "SSH password for bastion host (sensitive). Overrides provider default.",
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
			},
			"group": schema.StringAttribute{
				MarkdownDescription: "File group on remote. Defaults to the SSH user's primary group.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("root"),
			},
			"mode": schema.StringAttribute{
				MarkdownDescription: "File permissions in octal notation (e.g., '0644' for rw-r--r--) applied to all files. Must be 4 digits. Defaults to '0644'.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("0644"),
			},

			// Optional - sync options.
			"exclude": schema.ListAttribute{
				MarkdownDescription: "List of glob patterns to exclude from sync (e.g., `*.tmp`, `.git`, `.DS_Store`). Supports standard glob syntax with `*` and `?` wildcards.",
				Optional:            true,
				ElementType:         types.StringType,
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
				MarkdownDescription: "Combined SHA256 hash of all source files.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					directorySourceHashPlanModifier{},
				},
			},
			"file_count": schema.Int64Attribute{
				MarkdownDescription: "Number of files in the directory (including those in subdirectories) that were synced. Excludes files matching the exclude patterns.",
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					directoryFileCountPlanModifier{},
				},
			},
			"total_size": schema.Int64Attribute{
				MarkdownDescription: "Total size of all synced files in bytes.",
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					directoryTotalSizePlanModifier{},
				},
			},
			"file_hashes": schema.MapAttribute{
				MarkdownDescription: "Map of relative file paths to their SHA256 hashes.",
				Computed:            true,
				ElementType:         types.StringType,
				PlanModifiers: []planmodifier.Map{
					directoryFileHashesPlanModifier{},
				},
			},
		},
	}
}

func (r *DirectoryResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *DirectoryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DirectoryResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get exclude patterns.
	excludePatterns := r.getExcludePatterns(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Scan local directory.
	files, err := scanDirectory(data.Source.ValueString(), excludePatterns)
	if err != nil {
		resp.Diagnostics.AddError("Failed to scan source directory", err.Error())
		return
	}

	// Create SSH client.
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer client.Close()

	// Upload all files.
	fileHashes := make(map[string]string)
	var totalSize int64

	for _, file := range files {
		localPath := filepath.Join(data.Source.ValueString(), file.RelPath)
		remotePath := filepath.Join(data.Destination.ValueString(), file.RelPath)

		// Upload file.
		if err := client.UploadFile(localPath, remotePath); err != nil {
			resp.Diagnostics.AddError(
				"Failed to upload file",
				fmt.Sprintf("File: %s, Error: %s", file.RelPath, err.Error()),
			)
			return
		}

		// Set ownership and permissions.
		if err := client.SetFileAttributes(
			remotePath,
			data.Owner.ValueString(),
			data.Group.ValueString(),
			data.Mode.ValueString(),
		); err != nil {
			resp.Diagnostics.AddError(
				"Failed to set file attributes",
				fmt.Sprintf("File: %s, Error: %s", file.RelPath, err.Error()),
			)
			return
		}

		fileHashes[file.RelPath] = file.Hash
		totalSize += file.Size
	}

	// Calculate combined hash.
	combinedHash := computeCombinedHash(files)

	// Convert file hashes to types.Map
	fileHashesMap, diags := types.MapValueFrom(ctx, types.StringType, fileHashes)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set computed values.
	data.ID = types.StringValue(fmt.Sprintf("%s:%s", data.Host.ValueString(), data.Destination.ValueString()))
	data.SourceHash = types.StringValue(combinedHash)
	data.FileCount = types.Int64Value(int64(len(files)))
	data.TotalSize = types.Int64Value(totalSize)
	data.FileHashes = fileHashesMap

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DirectoryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DirectoryResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if source directory still exists.
	sourcePath := data.Source.ValueString()

	// If source is not set (e.g., after import), don't remove from state.
	// The user needs to update their config to include the source attribute.
	if sourcePath == "" || data.Source.IsNull() || data.Source.IsUnknown() {
		// Preserve the current state - source will be set in next apply.
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}

	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		resp.State.RemoveResource(ctx)
		return
	}

	// IMPORTANT: We do NOT update source_hash, file_count, total_size, or file_hashes here.
	// These represent what was last successfully synced to the remote, not the current local state.
	// This allows Terraform to detect local file changes during plan.
	//
	// The plan modifiers on these attributes compute the current local values
	// and trigger an update when they differ from the stored state.

	// State is unchanged - we preserve the existing computed values.
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DirectoryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data DirectoryResourceModel
	var state DirectoryResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get exclude patterns.
	excludePatterns := r.getExcludePatterns(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Scan local directory.
	files, err := scanDirectory(data.Source.ValueString(), excludePatterns)
	if err != nil {
		resp.Diagnostics.AddError("Failed to scan source directory", err.Error())
		return
	}

	// Get previous file hashes from state.
	var stateHashes map[string]string
	resp.Diagnostics.Append(state.FileHashes.ElementsAs(ctx, &stateHashes, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create SSH client.
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer client.Close()

	// Check if mode/owner/group changed - if so, we need to update all files.
	modeChanged := data.Mode.ValueString() != state.Mode.ValueString()
	ownerChanged := data.Owner.ValueString() != state.Owner.ValueString()
	groupChanged := data.Group.ValueString() != state.Group.ValueString()
	attributesChanged := modeChanged || ownerChanged || groupChanged

	// Upload changed files.
	newFileHashes := make(map[string]string)
	currentFiles := make(map[string]bool)
	var totalSize int64

	for _, file := range files {
		localPath := filepath.Join(data.Source.ValueString(), file.RelPath)
		remotePath := filepath.Join(data.Destination.ValueString(), file.RelPath)
		currentFiles[file.RelPath] = true

		// Check if file changed.
		oldHash, existed := stateHashes[file.RelPath]
		fileUnchanged := existed && oldHash == file.Hash

		if fileUnchanged && !attributesChanged {
			// File and attributes unchanged, skip entirely.
			newFileHashes[file.RelPath] = file.Hash
			totalSize += file.Size
			continue
		}

		if !fileUnchanged {
			// Upload file if content changed.
			if err := client.UploadFile(localPath, remotePath); err != nil {
				resp.Diagnostics.AddError(
					"Failed to upload file",
					fmt.Sprintf("File: %s, Error: %s", file.RelPath, err.Error()),
				)
				return
			}
		}

		// Set ownership and permissions (always if file was uploaded or attributes changed).
		if err := client.SetFileAttributes(
			remotePath,
			data.Owner.ValueString(),
			data.Group.ValueString(),
			data.Mode.ValueString(),
		); err != nil {
			resp.Diagnostics.AddError(
				"Failed to set file attributes",
				fmt.Sprintf("File: %s, Error: %s", file.RelPath, err.Error()),
			)
			return
		}

		newFileHashes[file.RelPath] = file.Hash
		totalSize += file.Size
	}

	// Delete files that no longer exist locally.
	for relPath := range stateHashes {
		if !currentFiles[relPath] {
			remotePath := filepath.Join(data.Destination.ValueString(), relPath)
			if err := client.DeleteFile(remotePath); err != nil {
				resp.Diagnostics.AddWarning(
					"Failed to delete removed file",
					fmt.Sprintf("File: %s, Error: %s", relPath, err.Error()),
				)
			}
		}
	}

	// Calculate combined hash.
	combinedHash := computeCombinedHash(files)

	// Convert file hashes to types.Map
	fileHashesMap, diags := types.MapValueFrom(ctx, types.StringType, newFileHashes)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set computed values.
	data.ID = types.StringValue(fmt.Sprintf("%s:%s", data.Host.ValueString(), data.Destination.ValueString()))
	data.SourceHash = types.StringValue(combinedHash)
	data.FileCount = types.Int64Value(int64(len(files)))
	data.TotalSize = types.Int64Value(totalSize)
	data.FileHashes = fileHashesMap

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DirectoryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data DirectoryResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get file hashes from state to know what to delete.
	var fileHashes map[string]string
	resp.Diagnostics.Append(data.FileHashes.ElementsAs(ctx, &fileHashes, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create SSH client.
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer client.Close()

	// Delete all synced files.
	for relPath := range fileHashes {
		remotePath := filepath.Join(data.Destination.ValueString(), relPath)
		if err := client.DeleteFile(remotePath); err != nil {
			resp.Diagnostics.AddWarning(
				"Failed to delete file",
				fmt.Sprintf("File: %s, Error: %s", relPath, err.Error()),
			)
		}
	}

	// Try to remove empty destination directory.
	// Note: This only removes the directory if it's empty.
	_ = client.DeleteFile(data.Destination.ValueString())
}

func (r *DirectoryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import format: "host:destination".
	// Example: "192.168.1.100:/etc/myapp"
	//
	// After import, the user must update the config to set:.
	// - source (required): path to the local source directory
	// - ssh_key_path or ssh_private_key (required): SSH credentials
	//
	// Then run `terraform apply` to sync state with the config.

	id := req.ID

	// Parse the import ID - format is "host:destination".
	// The destination is an absolute path, so we split on the first ":".
	colonIdx := strings.Index(id, ":")
	if colonIdx == -1 || colonIdx == 0 || colonIdx == len(id)-1 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf(
				"Import ID must be in format 'host:destination' (e.g., '192.168.1.100:/etc/myapp').\n"+
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

func (r *DirectoryResource) getExcludePatterns(ctx context.Context, data *DirectoryResourceModel, diags *diag.Diagnostics) []string {
	if data.Exclude.IsNull() || data.Exclude.IsUnknown() {
		return nil
	}

	var patterns []string
	d := data.Exclude.ElementsAs(ctx, &patterns, false)
	diags.Append(d...)
	return patterns
}

func (r *DirectoryResource) createSSHClient(data *DirectoryResourceModel) (ssh.ClientInterface, error) {
	config := ssh.Config{
		Host: data.Host.ValueString(),
		Port: int(data.SSHPort.ValueInt64()),
		User: data.SSHUser.ValueString(),
	}

	// Determine SSH credentials - resource values override provider defaults.
	// Check password authentication.
	if !data.SSHPassword.IsNull() && data.SSHPassword.ValueString() != "" {
		config.Password = data.SSHPassword.ValueString()
	} else if r.providerConfig != nil && !r.providerConfig.SSHPassword.IsNull() {
		config.Password = r.providerConfig.SSHPassword.ValueString()
	}

	// Check private key authentication.
	if !data.SSHPrivateKey.IsNull() && data.SSHPrivateKey.ValueString() != "" {
		config.PrivateKey = data.SSHPrivateKey.ValueString()
	} else if !data.SSHKeyPath.IsNull() && data.SSHKeyPath.ValueString() != "" {
		config.KeyPath = expandPath(data.SSHKeyPath.ValueString())
	} else if r.providerConfig != nil {
		if !r.providerConfig.SSHPrivateKey.IsNull() && r.providerConfig.SSHPrivateKey.ValueString() != "" {
			config.PrivateKey = r.providerConfig.SSHPrivateKey.ValueString()
		} else if !r.providerConfig.SSHKeyPath.IsNull() && r.providerConfig.SSHKeyPath.ValueString() != "" {
			config.KeyPath = expandPath(r.providerConfig.SSHKeyPath.ValueString())
		}
	}

	// Check certificate authentication.
	if !data.SSHCertificate.IsNull() && data.SSHCertificate.ValueString() != "" {
		config.Certificate = data.SSHCertificate.ValueString()
	} else if !data.SSHCertificatePath.IsNull() && data.SSHCertificatePath.ValueString() != "" {
		config.CertificatePath = expandPath(data.SSHCertificatePath.ValueString())
	} else if r.providerConfig != nil {
		if !r.providerConfig.SSHCertificate.IsNull() && r.providerConfig.SSHCertificate.ValueString() != "" {
			config.Certificate = r.providerConfig.SSHCertificate.ValueString()
		} else if !r.providerConfig.SSHCertificatePath.IsNull() && r.providerConfig.SSHCertificatePath.ValueString() != "" {
			config.CertificatePath = expandPath(r.providerConfig.SSHCertificatePath.ValueString())
		}
	}

	// Check bastion/jump host configuration.
	if !data.BastionHost.IsNull() && data.BastionHost.ValueString() != "" {
		config.BastionHost = data.BastionHost.ValueString()
		if !data.BastionPort.IsNull() {
			config.BastionPort = int(data.BastionPort.ValueInt64())
		}
		if !data.BastionUser.IsNull() && data.BastionUser.ValueString() != "" {
			config.BastionUser = data.BastionUser.ValueString()
		}
		if !data.BastionKey.IsNull() && data.BastionKey.ValueString() != "" {
			config.BastionKey = data.BastionKey.ValueString()
		} else if !data.BastionKeyPath.IsNull() && data.BastionKeyPath.ValueString() != "" {
			config.BastionKeyPath = expandPath(data.BastionKeyPath.ValueString())
		}
		if !data.BastionPassword.IsNull() && data.BastionPassword.ValueString() != "" {
			config.BastionPassword = data.BastionPassword.ValueString()
		}
	} else if r.providerConfig != nil && !r.providerConfig.BastionHost.IsNull() && r.providerConfig.BastionHost.ValueString() != "" {
		// Fall back to provider config for bastion.
		config.BastionHost = r.providerConfig.BastionHost.ValueString()
		if !r.providerConfig.BastionPort.IsNull() {
			config.BastionPort = int(r.providerConfig.BastionPort.ValueInt64())
		}
		if !r.providerConfig.BastionUser.IsNull() && r.providerConfig.BastionUser.ValueString() != "" {
			config.BastionUser = r.providerConfig.BastionUser.ValueString()
		}
		if !r.providerConfig.BastionKey.IsNull() && r.providerConfig.BastionKey.ValueString() != "" {
			config.BastionKey = r.providerConfig.BastionKey.ValueString()
		} else if !r.providerConfig.BastionKeyPath.IsNull() && r.providerConfig.BastionKeyPath.ValueString() != "" {
			config.BastionKeyPath = expandPath(r.providerConfig.BastionKeyPath.ValueString())
		}
		if !r.providerConfig.BastionPassword.IsNull() && r.providerConfig.BastionPassword.ValueString() != "" {
			config.BastionPassword = r.providerConfig.BastionPassword.ValueString()
		}
	}

	// Check insecure host key setting.
	if !data.InsecureIgnoreHostKey.IsNull() && data.InsecureIgnoreHostKey.ValueBool() {
		config.InsecureIgnoreHostKey = true
	} else if r.providerConfig != nil && !r.providerConfig.InsecureIgnoreHostKey.IsNull() {
		config.InsecureIgnoreHostKey = r.providerConfig.InsecureIgnoreHostKey.ValueBool()
	}

	factory := r.sshClientFactory
	if factory == nil {
		factory = DefaultSSHClientFactory
	}
	return factory(config)
}

// FileInfo holds information about a file in the source directory.
type FileInfo struct {
	RelPath string
	Hash    string
	Size    int64
}

// scanDirectory walks a directory and returns information about all files.
func scanDirectory(root string, excludePatterns []string) ([]FileInfo, error) {
	var files []FileInfo

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories.
		if d.IsDir() {
			return nil
		}

		// Get relative path.
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		// Check exclude patterns.
		if shouldExclude(relPath, excludePatterns) {
			return nil
		}

		// Calculate hash.
		hash, size, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("failed to hash %s: %w", relPath, err)
		}

		files = append(files, FileInfo{
			RelPath: relPath,
			Hash:    hash,
			Size:    size,
		})

		return nil
	})

	// Sort files for consistent ordering.
	sort.Slice(files, func(i, j int) bool {
		return files[i].RelPath < files[j].RelPath
	})

	return files, err
}

// shouldExclude checks if a path matches any exclude pattern.
func shouldExclude(path string, excludePatterns []string) bool {
	for _, pattern := range excludePatterns {
		// Check the filename.
		filename := filepath.Base(path)
		if matched, _ := filepath.Match(pattern, filename); matched {
			return true
		}
		// Check the full relative path.
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		// Check if any path component matches.
		parts := strings.Split(path, string(filepath.Separator))
		for _, part := range parts {
			if matched, _ := filepath.Match(pattern, part); matched {
				return true
			}
		}
	}
	return false
}

// computeCombinedHash computes a combined hash of all file hashes.
func computeCombinedHash(files []FileInfo) string {
	h := sha256.New()
	for _, file := range files {
		_, _ = io.WriteString(h, file.RelPath)
		_, _ = io.WriteString(h, ":")
		_, _ = io.WriteString(h, file.Hash)
		_, _ = io.WriteString(h, "\n")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// scanDirectoryForPlan scans a directory and returns file info and computed values.
// This is used by plan modifiers to compute the expected state during planning.
func scanDirectoryForPlan(ctx context.Context, req interface{ GetAttribute(context.Context, path.Path, interface{}) diag.Diagnostics }) ([]FileInfo, string, int64, int64, map[string]string, error) {
	// Get source path from plan.
	var sourcePath types.String
	if diags := req.GetAttribute(ctx, path.Root("source"), &sourcePath); diags.HasError() || sourcePath.IsUnknown() || sourcePath.IsNull() {
		return nil, "", 0, 0, nil, fmt.Errorf("source path not available")
	}

	// Get exclude patterns from plan.
	var excludeList types.List
	if diags := req.GetAttribute(ctx, path.Root("exclude"), &excludeList); diags.HasError() {
		return nil, "", 0, 0, nil, fmt.Errorf("exclude patterns not available")
	}

	var excludePatterns []string
	if !excludeList.IsNull() && !excludeList.IsUnknown() {
		for _, v := range excludeList.Elements() {
			if strVal, ok := v.(types.String); ok && !strVal.IsNull() && !strVal.IsUnknown() {
				excludePatterns = append(excludePatterns, strVal.ValueString())
			}
		}
	}

	// Scan the directory.
	files, err := scanDirectory(sourcePath.ValueString(), excludePatterns)
	if err != nil {
		return nil, "", 0, 0, nil, err
	}

	// Compute values.
	fileHashes := make(map[string]string)
	var totalSize int64
	for _, file := range files {
		fileHashes[file.RelPath] = file.Hash
		totalSize += file.Size
	}

	combinedHash := computeCombinedHash(files)
	fileCount := int64(len(files))

	return files, combinedHash, fileCount, totalSize, fileHashes, nil
}

// directorySourceHashPlanModifier computes the combined hash during planning.
type directorySourceHashPlanModifier struct{}

func (m directorySourceHashPlanModifier) Description(_ context.Context) string {
	return "Computes combined hash from current local source directory to detect changes."
}

func (m directorySourceHashPlanModifier) MarkdownDescription(_ context.Context) string {
	return "Computes combined hash from current local source directory to detect changes."
}

func (m directorySourceHashPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If resource is being destroyed, don't compute hash.
	if req.Plan.Raw.IsNull() {
		return
	}

	_, combinedHash, _, _, _, err := scanDirectoryForPlan(ctx, req.Plan)
	if err != nil {
		// Directory doesn't exist or can't be read - let Create/Update handle the error.
		resp.PlanValue = types.StringUnknown()
		return
	}

	resp.PlanValue = types.StringValue(combinedHash)
}

// directoryFileCountPlanModifier computes the file count during planning.
type directoryFileCountPlanModifier struct{}

func (m directoryFileCountPlanModifier) Description(_ context.Context) string {
	return "Computes file count from current local source directory."
}

func (m directoryFileCountPlanModifier) MarkdownDescription(_ context.Context) string {
	return "Computes file count from current local source directory."
}

func (m directoryFileCountPlanModifier) PlanModifyInt64(ctx context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	// If resource is being destroyed, don't compute.
	if req.Plan.Raw.IsNull() {
		return
	}

	_, _, fileCount, _, _, err := scanDirectoryForPlan(ctx, req.Plan)
	if err != nil {
		resp.PlanValue = types.Int64Unknown()
		return
	}

	resp.PlanValue = types.Int64Value(fileCount)
}

// directoryTotalSizePlanModifier computes the total size during planning.
type directoryTotalSizePlanModifier struct{}

func (m directoryTotalSizePlanModifier) Description(_ context.Context) string {
	return "Computes total size from current local source directory."
}

func (m directoryTotalSizePlanModifier) MarkdownDescription(_ context.Context) string {
	return "Computes total size from current local source directory."
}

func (m directoryTotalSizePlanModifier) PlanModifyInt64(ctx context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	// If resource is being destroyed, don't compute.
	if req.Plan.Raw.IsNull() {
		return
	}

	_, _, _, totalSize, _, err := scanDirectoryForPlan(ctx, req.Plan)
	if err != nil {
		resp.PlanValue = types.Int64Unknown()
		return
	}

	resp.PlanValue = types.Int64Value(totalSize)
}

// directoryFileHashesPlanModifier computes the file hashes map during planning.
type directoryFileHashesPlanModifier struct{}

func (m directoryFileHashesPlanModifier) Description(_ context.Context) string {
	return "Computes file hashes map from current local source directory."
}

func (m directoryFileHashesPlanModifier) MarkdownDescription(_ context.Context) string {
	return "Computes file hashes map from current local source directory."
}

func (m directoryFileHashesPlanModifier) PlanModifyMap(ctx context.Context, req planmodifier.MapRequest, resp *planmodifier.MapResponse) {
	// If resource is being destroyed, don't compute.
	if req.Plan.Raw.IsNull() {
		return
	}

	_, _, _, _, fileHashes, err := scanDirectoryForPlan(ctx, req.Plan)
	if err != nil {
		resp.PlanValue = types.MapUnknown(types.StringType)
		return
	}

	fileHashesMap, diags := types.MapValueFrom(ctx, types.StringType, fileHashes)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.PlanValue = fileHashesMap
}
