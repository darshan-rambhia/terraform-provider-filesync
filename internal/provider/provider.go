package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure FilesyncProvider satisfies various provider interfaces.
var _ provider.Provider = &FilesyncProvider{}

// FilesyncProvider defines the provider implementation.
type FilesyncProvider struct {
	version string
}

// FilesyncProviderModel describes the provider data model.
type FilesyncProviderModel struct {
	// Default SSH settings that can be overridden per-resource.
	SSHUser       types.String `tfsdk:"ssh_user"`
	SSHPrivateKey types.String `tfsdk:"ssh_private_key"`
	SSHKeyPath    types.String `tfsdk:"ssh_key_path"`
	SSHPort       types.Int64  `tfsdk:"ssh_port"`

	// Additional authentication methods.
	SSHPassword        types.String `tfsdk:"ssh_password"`
	SSHCertificate     types.String `tfsdk:"ssh_certificate"`
	SSHCertificatePath types.String `tfsdk:"ssh_certificate_path"`

	// Bastion/Jump host settings.
	BastionHost     types.String `tfsdk:"bastion_host"`
	BastionPort     types.Int64  `tfsdk:"bastion_port"`
	BastionUser     types.String `tfsdk:"bastion_user"`
	BastionKey      types.String `tfsdk:"bastion_private_key"`
	BastionKeyPath  types.String `tfsdk:"bastion_key_path"`
	BastionPassword types.String `tfsdk:"bastion_password"`

	// Connection pooling.
	ConnectionPoolEnabled types.Bool `tfsdk:"connection_pool_enabled"`

	// Host key verification.
	InsecureIgnoreHostKey types.Bool `tfsdk:"insecure_ignore_host_key"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &FilesyncProvider{
			version: version,
		}
	}
}

func (p *FilesyncProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "filesync"
	resp.Version = p.version
}

func (p *FilesyncProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `
The filesync provider enables declarative file synchronization to remote hosts via SSH/SFTP.

Unlike traditional provisioners, this provider:
- Tracks file state properly in Terraform state
- Detects drift on apply (fails if remote was modified externally)
- Supports plan-time change detection based on local file hashes

## Example Usage

` + "```hcl" + `
provider "filesync" {
  ssh_user     = "root"
  ssh_key_path = "~/.ssh/id_ed25519"
}

resource "filesync_file" "config" {
  source      = "./config/app.conf"
  destination = "/etc/myapp/app.conf"
  host        = "192.168.1.100"
  mode        = "0644"
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			"ssh_user": schema.StringAttribute{
				MarkdownDescription: "Default SSH user for connections. Can be overridden per-resource.",
				Optional:            true,
			},
			"ssh_private_key": schema.StringAttribute{
				MarkdownDescription: "Default SSH private key content (sensitive). Mutually exclusive with ssh_key_path.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_key_path": schema.StringAttribute{
				MarkdownDescription: "Default path to SSH private key file. Mutually exclusive with ssh_private_key.",
				Optional:            true,
			},
			"ssh_port": schema.Int64Attribute{
				MarkdownDescription: "Default SSH port. Defaults to 22.",
				Optional:            true,
			},
			"ssh_password": schema.StringAttribute{
				MarkdownDescription: "Default SSH password for password authentication (sensitive). Use this as an alternative to key-based authentication.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_certificate": schema.StringAttribute{
				MarkdownDescription: "Default SSH certificate content for certificate authentication. Used with ssh_private_key or ssh_key_path.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_certificate_path": schema.StringAttribute{
				MarkdownDescription: "Default path to SSH certificate file for certificate authentication. Used with ssh_private_key or ssh_key_path.",
				Optional:            true,
			},
			"bastion_host": schema.StringAttribute{
				MarkdownDescription: "Default bastion/jump host address for multi-hop SSH connections.",
				Optional:            true,
			},
			"bastion_port": schema.Int64Attribute{
				MarkdownDescription: "Default bastion host SSH port. Defaults to 22.",
				Optional:            true,
			},
			"bastion_user": schema.StringAttribute{
				MarkdownDescription: "Default SSH user for bastion host. Falls back to ssh_user if not set.",
				Optional:            true,
			},
			"bastion_private_key": schema.StringAttribute{
				MarkdownDescription: "Default SSH private key content for bastion host (sensitive). Falls back to ssh_private_key if not set.",
				Optional:            true,
				Sensitive:           true,
			},
			"bastion_key_path": schema.StringAttribute{
				MarkdownDescription: "Default path to SSH private key file for bastion host. Falls back to ssh_key_path if not set.",
				Optional:            true,
			},
			"bastion_password": schema.StringAttribute{
				MarkdownDescription: "Default SSH password for bastion host (sensitive).",
				Optional:            true,
				Sensitive:           true,
			},
			"connection_pool_enabled": schema.BoolAttribute{
				MarkdownDescription: "Enable SSH connection pooling for improved performance when managing multiple files on the same host. Connections are reused across resources and automatically cleaned up after 5 minutes of inactivity. Defaults to false.",
				Optional:            true,
			},
			"insecure_ignore_host_key": schema.BoolAttribute{
				MarkdownDescription: "Skip SSH host key verification. WARNING: This is insecure and should only be used for testing or in trusted environments. Defaults to false.",
				Optional:            true,
			},
		},
	}
}

func (p *FilesyncProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config FilesyncProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Make provider config available to resources.
	resp.DataSourceData = &config
	resp.ResourceData = &config
}

func (p *FilesyncProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewFileResource,
		NewDirectoryResource,
	}
}

func (p *FilesyncProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewHostDataSource,
	}
}
