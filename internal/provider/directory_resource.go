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
	"sync"

	"github.com/darshan-rambhia/gosftp"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	InsecureIgnoreHostKey types.Bool   `tfsdk:"insecure_ignore_host_key"`
	KnownHostsFile        types.String `tfsdk:"known_hosts_file"`
	StrictHostKeyChecking types.String `tfsdk:"strict_host_key_checking"`

	// Optional - file attributes.
	Owner types.String `tfsdk:"owner"`
	Group types.String `tfsdk:"group"`
	Mode  types.String `tfsdk:"mode"`

	// Optional - sync options.
	Exclude         types.List   `tfsdk:"exclude"`
	ParallelUploads types.Int64  `tfsdk:"parallel_uploads"`
	SymlinkPolicy   types.String `tfsdk:"symlink_policy"`

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
				MarkdownDescription: "File permissions in octal notation (e.g., '0644' for rw-r--r--) applied to all files. Must be 3-4 digits. Defaults to '0644'.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("0644"),
				Validators: []validator.String{
					OctalMode(),
				},
			},

			// Optional - sync options.
			"exclude": schema.ListAttribute{
				MarkdownDescription: "List of glob patterns to exclude from sync (e.g., `*.tmp`, `.git`, `.DS_Store`). Supports standard glob syntax with `*` and `?` wildcards.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"parallel_uploads": schema.Int64Attribute{
				MarkdownDescription: "Number of files to upload in parallel. Set to 1 for sequential uploads. Higher values improve performance but use more connections. Defaults to 4.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(4),
				Validators: []validator.Int64{
					int64validator.Between(1, 32),
				},
			},
			"symlink_policy": schema.StringAttribute{
				MarkdownDescription: "How to handle symbolic links. Options: `follow` (default) - follow symlinks and copy target content; `skip` - ignore symlinks; `preserve` - create symlinks on remote (requires remote support).",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("follow"),
				Validators: []validator.String{
					stringvalidator.OneOf("follow", "skip", "preserve"),
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

	ctx = tflog.SetField(ctx, "host", data.Host.ValueString())
	ctx = tflog.SetField(ctx, "source", data.Source.ValueString())
	ctx = tflog.SetField(ctx, "destination", data.Destination.ValueString())

	tflog.Info(ctx, "Creating directory resource")

	// Get exclude patterns.
	excludePatterns := r.getExcludePatterns(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Scan local directory.
	symlinkPolicy := data.SymlinkPolicy.ValueString()
	tflog.Debug(ctx, "Scanning source directory", map[string]interface{}{
		"exclude_patterns": excludePatterns,
		"symlink_policy":   symlinkPolicy,
	})
	files, err := scanDirectory(data.Source.ValueString(), excludePatterns, symlinkPolicy)
	if err != nil {
		resp.Diagnostics.AddError("Failed to scan source directory", err.Error())
		return
	}
	tflog.Debug(ctx, "Source directory scanned", map[string]interface{}{
		"file_count": len(files),
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

	// Prepare upload jobs.
	parallelism := int(data.ParallelUploads.ValueInt64())
	jobs := make([]uploadJob, 0, len(files))
	for _, file := range files {
		jobs = append(jobs, uploadJob{
			file:       file,
			localPath:  filepath.Join(data.Source.ValueString(), file.RelPath),
			remotePath: filepath.Join(data.Destination.ValueString(), file.RelPath),
			owner:      data.Owner.ValueString(),
			group:      data.Group.ValueString(),
			mode:       data.Mode.ValueString(),
		})
	}

	tflog.Debug(ctx, "Starting parallel file uploads", map[string]interface{}{
		"total_files": len(files),
		"parallelism": parallelism,
	})

	// Upload all files in parallel.
	results := parallelUpload(ctx, client, jobs, parallelism)

	// Process results.
	fileHashes := make(map[string]string)
	var totalSize int64
	var uploadErrors []string

	for _, result := range results {
		if result.err != nil {
			uploadErrors = append(uploadErrors, fmt.Sprintf("%s: %s", result.relPath, result.err.Error()))
		} else {
			fileHashes[result.relPath] = result.hash
			totalSize += result.size
		}
	}

	// Report any errors.
	if len(uploadErrors) > 0 {
		resp.Diagnostics.AddError(
			"Failed to upload files",
			fmt.Sprintf("The following files failed to upload:\n%s", strings.Join(uploadErrors, "\n")),
		)
		return
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

	tflog.Info(ctx, "Directory resource created successfully", map[string]interface{}{
		"id":         data.ID.ValueString(),
		"file_count": len(files),
		"total_size": totalSize,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DirectoryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DirectoryResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "id", data.ID.ValueString())
	tflog.Debug(ctx, "Reading directory resource state")

	// Check if source directory still exists.
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
		tflog.Info(ctx, "Source directory no longer exists, removing resource from state", map[string]interface{}{
			"source": sourcePath,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// IMPORTANT: We do NOT update source_hash, file_count, total_size, or file_hashes here.
	// These represent what was last successfully synced to the remote, not the current local state.
	// This allows Terraform to detect local file changes during plan.
	//
	// The plan modifiers on these attributes compute the current local values
	// and trigger an update when they differ from the stored state.

	tflog.Debug(ctx, "Directory resource state preserved")
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

	ctx = tflog.SetField(ctx, "host", data.Host.ValueString())
	ctx = tflog.SetField(ctx, "source", data.Source.ValueString())
	ctx = tflog.SetField(ctx, "destination", data.Destination.ValueString())

	tflog.Info(ctx, "Updating directory resource")

	// Get exclude patterns.
	excludePatterns := r.getExcludePatterns(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Scan local directory.
	symlinkPolicy := data.SymlinkPolicy.ValueString()
	tflog.Debug(ctx, "Scanning source directory", map[string]interface{}{
		"symlink_policy": symlinkPolicy,
	})
	files, err := scanDirectory(data.Source.ValueString(), excludePatterns, symlinkPolicy)
	if err != nil {
		resp.Diagnostics.AddError("Failed to scan source directory", err.Error())
		return
	}
	tflog.Debug(ctx, "Source directory scanned", map[string]interface{}{
		"file_count": len(files),
	})

	// Get previous file hashes from state.
	var stateHashes map[string]string
	resp.Diagnostics.Append(state.FileHashes.ElementsAs(ctx, &stateHashes, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create SSH client.
	tflog.Debug(ctx, "Establishing SSH connection")
	client, err := r.createSSHClient(&data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create SSH connection", err.Error())
		return
	}
	defer r.releaseSSHClient(&data, client)
	tflog.Debug(ctx, "SSH connection established")

	// Check if mode/owner/group changed - if so, we need to update all files.
	modeChanged := data.Mode.ValueString() != state.Mode.ValueString()
	ownerChanged := data.Owner.ValueString() != state.Owner.ValueString()
	groupChanged := data.Group.ValueString() != state.Group.ValueString()
	attributesChanged := modeChanged || ownerChanged || groupChanged

	if attributesChanged {
		tflog.Debug(ctx, "File attributes changed, will update all files", map[string]interface{}{
			"mode_changed":  modeChanged,
			"owner_changed": ownerChanged,
			"group_changed": groupChanged,
		})
	}

	// Categorize files: unchanged (skip), need upload, or need attribute update only.
	newFileHashes := make(map[string]string)
	currentFiles := make(map[string]bool)
	var totalSize int64
	var skippedCount int
	var jobs []uploadJob

	for _, file := range files {
		currentFiles[file.RelPath] = true

		// Check if file changed.
		oldHash, existed := stateHashes[file.RelPath]
		fileUnchanged := existed && oldHash == file.Hash

		if fileUnchanged && !attributesChanged {
			// File and attributes unchanged, skip entirely.
			newFileHashes[file.RelPath] = file.Hash
			totalSize += file.Size
			skippedCount++
			continue
		}

		// File needs upload or attribute update.
		jobs = append(jobs, uploadJob{
			file:       file,
			localPath:  filepath.Join(data.Source.ValueString(), file.RelPath),
			remotePath: filepath.Join(data.Destination.ValueString(), file.RelPath),
			owner:      data.Owner.ValueString(),
			group:      data.Group.ValueString(),
			mode:       data.Mode.ValueString(),
		})
	}

	// Upload changed files in parallel.
	parallelism := int(data.ParallelUploads.ValueInt64())
	tflog.Debug(ctx, "Starting parallel file uploads", map[string]interface{}{
		"files_to_upload": len(jobs),
		"files_skipped":   skippedCount,
		"parallelism":     parallelism,
	})

	var uploadedCount int
	var uploadErrors []string

	if len(jobs) > 0 {
		results := parallelUpload(ctx, client, jobs, parallelism)

		for _, result := range results {
			if result.err != nil {
				uploadErrors = append(uploadErrors, fmt.Sprintf("%s: %s", result.relPath, result.err.Error()))
			} else {
				newFileHashes[result.relPath] = result.hash
				totalSize += result.size
				uploadedCount++
			}
		}

		// Report any errors.
		if len(uploadErrors) > 0 {
			resp.Diagnostics.AddError(
				"Failed to upload files",
				fmt.Sprintf("The following files failed to upload:\n%s", strings.Join(uploadErrors, "\n")),
			)
			return
		}
	}

	// Delete files that no longer exist locally.
	var deletedCount int
	for relPath := range stateHashes {
		if !currentFiles[relPath] {
			tflog.Debug(ctx, "Deleting removed file", map[string]interface{}{
				"file": relPath,
			})
			remotePath := filepath.Join(data.Destination.ValueString(), relPath)
			if err := client.DeleteFile(ctx, remotePath); err != nil {
				resp.Diagnostics.AddWarning(
					"Failed to delete removed file",
					fmt.Sprintf("File: %s, Error: %s", relPath, err.Error()),
				)
			} else {
				deletedCount++
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

	tflog.Info(ctx, "Directory resource updated successfully", map[string]interface{}{
		"id":             data.ID.ValueString(),
		"files_uploaded": uploadedCount,
		"files_skipped":  skippedCount,
		"files_deleted":  deletedCount,
		"total_files":    len(files),
		"total_size":     totalSize,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DirectoryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data DirectoryResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "host", data.Host.ValueString())
	ctx = tflog.SetField(ctx, "destination", data.Destination.ValueString())
	ctx = tflog.SetField(ctx, "id", data.ID.ValueString())

	tflog.Info(ctx, "Deleting directory resource")

	// Get file hashes from state to know what to delete.
	var fileHashes map[string]string
	resp.Diagnostics.Append(data.FileHashes.ElementsAs(ctx, &fileHashes, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Files to delete", map[string]interface{}{
		"file_count": len(fileHashes),
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

	// Delete all synced files.
	var deletedCount, failedCount int
	for relPath := range fileHashes {
		remotePath := filepath.Join(data.Destination.ValueString(), relPath)
		if err := client.DeleteFile(ctx, remotePath); err != nil {
			resp.Diagnostics.AddWarning(
				"Failed to delete file",
				fmt.Sprintf("File: %s, Error: %s", relPath, err.Error()),
			)
			failedCount++
		} else {
			deletedCount++
		}
	}

	// Try to remove empty destination directory.
	// Note: This only removes the directory if it's empty.
	_ = client.DeleteFile(ctx, data.Destination.ValueString())

	tflog.Info(ctx, "Directory resource deleted", map[string]interface{}{
		"files_deleted": deletedCount,
		"files_failed":  failedCount,
	})
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
	tflog.Info(ctx, "Importing directory resource", map[string]interface{}{
		"import_id": id,
	})

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

// isPoolingEnabled checks if connection pooling is enabled.
func (r *DirectoryResource) isPoolingEnabled() bool {
	return r.providerConfig != nil &&
		!r.providerConfig.ConnectionPoolEnabled.IsNull() &&
		r.providerConfig.ConnectionPoolEnabled.ValueBool()
}

// createSSHClient creates or retrieves an SSH client (from pool if enabled).
func (r *DirectoryResource) createSSHClient(data *DirectoryResourceModel) (gosftp.ClientInterface, error) {
	config := BuildSSHConfig(data, r.providerConfig)

	// Use connection pool if enabled.
	if r.isPoolingEnabled() && r.providerConfig != nil && r.providerConfig.pool != nil {
		return r.providerConfig.pool.GetOrCreate(config)
	}

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
func (r *DirectoryResource) releaseSSHClient(data *DirectoryResourceModel, client gosftp.ClientInterface) {
	if r.isPoolingEnabled() && r.providerConfig != nil && r.providerConfig.pool != nil {
		config := BuildSSHConfig(data, r.providerConfig)
		r.providerConfig.pool.Release(config)
		// Don't close - the pool manages the connection lifecycle.
	} else {
		// Not pooling - close the connection.
		client.Close()
	}
}

// uploadJob represents a file upload job for the worker pool.
type uploadJob struct {
	file       FileInfo
	localPath  string
	remotePath string
	owner      string
	group      string
	mode       string
}

// uploadResult represents the result of an upload job.
type uploadResult struct {
	relPath string
	hash    string
	size    int64
	err     error
}

// parallelUpload uploads files in parallel using a worker pool.
func parallelUpload(
	ctx context.Context,
	client gosftp.ClientInterface,
	jobs []uploadJob,
	parallelism int,
) []uploadResult {
	if parallelism < 1 {
		parallelism = 1
	}
	if parallelism > len(jobs) {
		parallelism = len(jobs)
	}

	jobChan := make(chan uploadJob, len(jobs))
	resultChan := make(chan uploadResult, len(jobs))

	// Start workers.
	var wg sync.WaitGroup
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				result := uploadResult{
					relPath: job.file.RelPath,
					hash:    job.file.Hash,
					size:    job.file.Size,
				}

				// Check for context cancellation.
				if ctx.Err() != nil {
					result.err = ctx.Err()
					resultChan <- result
					continue
				}

				// Upload file.
				if err := client.UploadFile(ctx, job.localPath, job.remotePath); err != nil {
					result.err = fmt.Errorf("upload failed: %w", err)
					resultChan <- result
					continue
				}

				// Set file attributes.
				if err := client.SetFileAttributes(ctx, job.remotePath, job.owner, job.group, job.mode); err != nil {
					result.err = fmt.Errorf("set attributes failed: %w", err)
					resultChan <- result
					continue
				}

				resultChan <- result
			}
		}()
	}

	// Send all jobs.
	for _, job := range jobs {
		jobChan <- job
	}
	close(jobChan)

	// Wait for all workers to finish.
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results.
	results := make([]uploadResult, 0, len(jobs))
	for result := range resultChan {
		results = append(results, result)
	}

	return results
}

// FileInfo holds information about a file in the source directory.
type FileInfo struct {
	RelPath       string
	Hash          string
	Size          int64
	IsSymlink     bool
	SymlinkTarget string // Only set if IsSymlink is true
}

// scanDirectory walks a directory and returns information about all files.
// symlinkPolicy can be: "follow" (dereference), "skip" (ignore), or "preserve" (keep as symlinks).
func scanDirectory(root string, excludePatterns []string, symlinkPolicy string) ([]FileInfo, error) {
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

		// Check if this is a symlink.
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("failed to get info for %s: %w", relPath, err)
		}

		isSymlink := info.Mode()&os.ModeSymlink != 0

		if isSymlink {
			switch symlinkPolicy {
			case "skip":
				// Skip symlinks entirely.
				return nil
			case "preserve":
				// Get the symlink target.
				target, err := os.Readlink(path)
				if err != nil {
					return fmt.Errorf("failed to read symlink %s: %w", relPath, err)
				}

				// For preserve mode, we don't hash the content - we store the target.
				// Use a hash of the target path for change detection.
				targetHash := fmt.Sprintf("symlink:%s", target)

				files = append(files, FileInfo{
					RelPath:       relPath,
					Hash:          targetHash,
					Size:          0,
					IsSymlink:     true,
					SymlinkTarget: target,
				})
				return nil
			default:
				// "follow" - continue below to hash the actual content.
			}
		}

		// Calculate hash of actual file content (follows symlinks automatically).
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
func scanDirectoryForPlan(ctx context.Context, req interface {
	GetAttribute(context.Context, path.Path, any) diag.Diagnostics
}) (string, int64, int64, map[string]string, error) {
	// Get source path from plan.
	var sourcePath types.String
	if diags := req.GetAttribute(ctx, path.Root("source"), &sourcePath); diags.HasError() || sourcePath.IsUnknown() || sourcePath.IsNull() {
		return "", 0, 0, nil, fmt.Errorf("source path not available")
	}

	// Get exclude patterns from plan.
	var excludeList types.List
	if diags := req.GetAttribute(ctx, path.Root("exclude"), &excludeList); diags.HasError() {
		return "", 0, 0, nil, fmt.Errorf("exclude patterns not available")
	}

	var excludePatterns []string
	if !excludeList.IsNull() && !excludeList.IsUnknown() {
		for _, v := range excludeList.Elements() {
			if strVal, ok := v.(types.String); ok && !strVal.IsNull() && !strVal.IsUnknown() {
				excludePatterns = append(excludePatterns, strVal.ValueString())
			}
		}
	}

	// Get symlink policy from plan.
	var symlinkPolicy types.String
	if diags := req.GetAttribute(ctx, path.Root("symlink_policy"), &symlinkPolicy); diags.HasError() {
		return "", 0, 0, nil, fmt.Errorf("symlink policy not available")
	}
	policy := "follow" // Default.
	if !symlinkPolicy.IsNull() && !symlinkPolicy.IsUnknown() {
		policy = symlinkPolicy.ValueString()
	}

	// Scan the directory.
	files, err := scanDirectory(sourcePath.ValueString(), excludePatterns, policy)
	if err != nil {
		return "", 0, 0, nil, err
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

	return combinedHash, fileCount, totalSize, fileHashes, nil
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

	combinedHash, _, _, _, err := scanDirectoryForPlan(ctx, req.Plan)
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

	_, fileCount, _, _, err := scanDirectoryForPlan(ctx, req.Plan)
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

	_, _, totalSize, _, err := scanDirectoryForPlan(ctx, req.Plan)
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

	_, _, _, fileHashes, err := scanDirectoryForPlan(ctx, req.Plan)
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
