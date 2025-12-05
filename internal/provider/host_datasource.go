package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &HostDataSource{}

func NewHostDataSource() datasource.DataSource {
	return &HostDataSource{}
}

// HostDataSource defines the data source implementation.
type HostDataSource struct{}

// HostDataSourceModel describes the data source data model.
type HostDataSourceModel struct {
	// Required.
	Address types.String `tfsdk:"address"`

	// Optional - connection settings.
	SSHUser            types.String `tfsdk:"ssh_user"`
	SSHPrivateKey      types.String `tfsdk:"ssh_private_key"`
	SSHKeyPath         types.String `tfsdk:"ssh_key_path"`
	SSHPort            types.Int64  `tfsdk:"ssh_port"`
	SSHPassword        types.String `tfsdk:"ssh_password"`
	SSHCertificate     types.String `tfsdk:"ssh_certificate"`
	SSHCertificatePath types.String `tfsdk:"ssh_certificate_path"`

	// Computed.
	ID types.String `tfsdk:"id"`
}

func (d *HostDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_host"
}

func (d *HostDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `
Defines a reusable host configuration for file synchronization.

This data source allows you to define SSH connection parameters once and reuse them across multiple filesync_file or filesync_directory resources. This is especially useful when managing files on multiple hosts with different credentials.

## Example Usage

### Single Host Configuration

` + "```hcl" + `
data "filesync_host" "webserver" {
  address      = "192.168.1.100"
  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/deploy_key"
  ssh_port     = 22
}

resource "filesync_file" "nginx_config" {
  source      = "${path.module}/configs/nginx.conf"
  destination = "/etc/nginx/nginx.conf"
  host        = data.filesync_host.webserver.address

  ssh_user     = data.filesync_host.webserver.ssh_user
  ssh_key_path = data.filesync_host.webserver.ssh_key_path
  ssh_port     = data.filesync_host.webserver.ssh_port
  mode         = "0644"
}
` + "```" + `

### Multiple Hosts with for_each

` + "```hcl" + `
locals {
  host_configs = {
    webserver = {
      address      = "192.168.1.100"
      ssh_user     = "deploy"
      ssh_key_path = "~/.ssh/deploy_key"
    }
    database = {
      address      = "192.168.1.101"
      ssh_user     = "admin"
      ssh_key_path = "~/.ssh/admin_key"
    }
  }
}

data "filesync_host" "servers" {
  for_each = local.host_configs

  address      = each.value.address
  ssh_user     = each.value.ssh_user
  ssh_key_path = each.value.ssh_key_path
}

resource "filesync_file" "common_config" {
  for_each = data.filesync_host.servers

  source      = "${path.module}/configs/common.conf"
  destination = "/etc/app/common.conf"
  host        = each.value.address

  ssh_user     = each.value.ssh_user
  ssh_key_path = each.value.ssh_key_path
  mode         = "0644"
}
` + "```" + `

### Password Authentication

` + "```hcl" + `
data "filesync_host" "legacy_server" {
  address      = "192.168.1.200"
  ssh_user     = "admin"
  ssh_password = var.legacy_server_password
}
` + "```" + `

### Certificate Authentication

` + "```hcl" + `
data "filesync_host" "secure_server" {
  address              = "192.168.1.50"
  ssh_user             = "deploy"
  ssh_key_path         = "~/.ssh/id_ed25519"
  ssh_certificate_path = "~/.ssh/id_ed25519-cert.pub"
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			// Required.
			"address": schema.StringAttribute{
				MarkdownDescription: "Host address as IP or hostname. Required field for data source lookup.",
				Required:            true,
			},

			// Optional - connection settings.
			"ssh_user": schema.StringAttribute{
				MarkdownDescription: "SSH username for authentication on this host. Defaults to current system user if not specified.",
				Optional:            true,
			},
			"ssh_private_key": schema.StringAttribute{
				MarkdownDescription: "SSH private key content in PEM format. Mutually exclusive with ssh_key_path. Sensitive field not stored in state.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_key_path": schema.StringAttribute{
				MarkdownDescription: "Path to SSH private key file. Can be absolute or relative. Mutually exclusive with ssh_private_key. Supports ~ expansion.",
				Optional:            true,
			},
			"ssh_port": schema.Int64Attribute{
				MarkdownDescription: "SSH listening port on this host. Must be between 1 and 65535. Defaults to 22 if not specified.",
				Optional:            true,
			},
			"ssh_password": schema.StringAttribute{
				MarkdownDescription: "SSH password for password authentication. Required if not using key-based authentication. Sensitive field not stored in state.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_certificate": schema.StringAttribute{
				MarkdownDescription: "SSH certificate content in OpenSSH format. Used with ssh_private_key for certificate-based authentication. Sensitive field not stored in state.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_certificate_path": schema.StringAttribute{
				MarkdownDescription: "Path to SSH certificate file in OpenSSH format. Used with ssh_key_path for certificate-based authentication. Supports ~ expansion.",
				Optional:            true,
			},

			// Computed.
			"id": schema.StringAttribute{
				MarkdownDescription: "Unique identifier computed from host address. Format: 'host:<address>'.",
				Computed:            true,
			},
		},
	}
}

func (d *HostDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data HostDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Generate a unique ID based on the address.
	data.ID = types.StringValue(fmt.Sprintf("host:%s", data.Address.ValueString()))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
