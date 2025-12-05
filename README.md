# Terraform Provider Filesync

A native Terraform/OpenTofu provider for declarative file synchronization to remote hosts via SSH/SFTP.

[![Tests](https://github.com/darshan-rambhia/terraform-provider-filesync/actions/workflows/test.yml/badge.svg)](https://github.com/darshan-rambhia/terraform-provider-filesync/actions/workflows/test.yml)
[![Lint](https://github.com/darshan-rambhia/terraform-provider-filesync/actions/workflows/lint.yml/badge.svg)](https://github.com/darshan-rambhia/terraform-provider-filesync/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/darshan-rambhia/terraform-provider-filesync/graph/badge.svg)](https://codecov.io/gh/darshan-rambhia/terraform-provider-filesync)
[![Terraform Registry Version](https://img.shields.io/badge/registry-v0.1.0-blue?logo=terraform)](https://registry.terraform.io/providers/darshan-rambhia/filesync/latest)
[![Go Version](https://img.shields.io/badge/go-1.21-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Overview

Traditional Terraform provisioners have a fundamental "state problem":

- No real state tracking (only trigger hashes)
- Cannot detect remote drift
- Partial failures leave inconsistent state
- Cannot show file-level changes in `terraform plan`

This provider solves these issues by treating each file as a first-class Terraform resource with explicit state tracking.

## Features

- **One resource per file** - Explicit state tracking (~300 bytes per file)
- **Plan-time change detection** - Shows file changes without connecting to remote
- **Drift detection on apply** - Detects and reports when remote files were modified outside Terraform (with content diff)
- **Fast plan, thorough apply** - Plan only checks local hashes; apply validates remote state
- **Multiple SSH auth methods** - Private key, password, and certificate authentication
- **SSH/SFTP transport** - Secure file transfer using standard SSH authentication

## Installation

### From Terraform Registry

```hcl
terraform {
  required_providers {
    filesync = {
      source  = "darshan-rambhia/filesync"
      version = "0.1.0"
    }
  }
}
```

### Local Development

```bash
# Clone the repository
git clone https://github.com/darshan-rambhia/terraform-provider-filesync.git
cd terraform-provider-filesync

# Build and install locally
task dev
```

## Usage

### Provider Configuration

```hcl
provider "filesync" {
  # Default SSH settings (can be overridden per-resource)
  ssh_user     = "root"
  ssh_key_path = "~/.ssh/id_ed25519"
  # Or use inline key:
  # ssh_private_key = var.ssh_private_key

  # Password authentication (alternative to key-based):
  # ssh_password = var.ssh_password

  # Certificate authentication (with private key):
  # ssh_certificate_path = "~/.ssh/id_ed25519-cert.pub"

  # Bastion/jump host for multi-hop SSH (optional):
  # bastion_host     = "bastion.example.com"
  # bastion_user     = "jumpuser"
  # bastion_key_path = "~/.ssh/bastion_key"
}
```

### Basic Example

```hcl
resource "filesync_file" "nginx_config" {
  source      = "${path.module}/files/nginx.conf"
  destination = "/etc/nginx/nginx.conf"
  host        = "192.168.1.100"

  owner = "root"
  group = "root"
  mode  = "0644"
}

resource "filesync_file" "env" {
  source      = "${path.module}/files/.env"
  destination = "/config/.env"
  host        = "192.168.1.100"
  mode        = "0600"  # Only owner can read
}

output "nginx_hash" {
  value = filesync_file.nginx_config.source_hash
}
```

### Multiple Hosts

```hcl
locals {
  hosts = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
}

resource "filesync_file" "app_config" {
  for_each = toset(local.hosts)

  source      = "${path.module}/files/app.conf"
  destination = "/etc/myapp/app.conf"
  host        = each.value
  mode        = "0644"
}
```

### Multiple Hosts with Different Credentials

When targeting multiple hosts with different SSH credentials, use a locals map to define host configurations:

```hcl
locals {
  hosts = {
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
    cache = {
      address      = "192.168.1.102"
      ssh_user     = "root"
      ssh_key_path = "~/.ssh/root_key"
    }
  }
}

provider "filesync" {}

resource "filesync_file" "nginx_config" {
  source      = "${path.module}/configs/nginx.conf"
  destination = "/etc/nginx/nginx.conf"
  host        = local.hosts.webserver.address

  ssh_user     = local.hosts.webserver.ssh_user
  ssh_key_path = local.hosts.webserver.ssh_key_path
  mode         = "0644"
}

resource "filesync_file" "pg_config" {
  source      = "${path.module}/configs/postgresql.conf"
  destination = "/etc/postgresql/postgresql.conf"
  host        = local.hosts.database.address

  ssh_user     = local.hosts.database.ssh_user
  ssh_key_path = local.hosts.database.ssh_key_path
  mode         = "0644"
}

# Sync same file to multiple hosts with for_each
resource "filesync_file" "common_config" {
  for_each = local.hosts

  source      = "${path.module}/configs/common.conf"
  destination = "/etc/app/common.conf"
  host        = each.value.address

  ssh_user     = each.value.ssh_user
  ssh_key_path = each.value.ssh_key_path
  mode         = "0644"
}
```

## Resource: filesync_file

Manages a single file on a remote host via SSH/SFTP.

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `source` | String | Local file path to sync |
| `destination` | String | Remote absolute path on target host |
| `host` | String | Remote host address (IP or hostname) |

### Optional Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ssh_user` | String | `"root"` | SSH username |
| `ssh_private_key` | String | - | SSH private key content (sensitive) |
| `ssh_key_path` | String | - | Path to SSH private key file |
| `ssh_port` | Number | `22` | SSH port |
| `ssh_password` | String | - | SSH password for password auth (sensitive) |
| `ssh_certificate` | String | - | SSH certificate content (sensitive) |
| `ssh_certificate_path` | String | - | Path to SSH certificate file |
| `bastion_host` | String | - | Bastion/jump host address for multi-hop SSH |
| `bastion_port` | Number | `22` | Bastion host SSH port |
| `bastion_user` | String | - | SSH user for bastion (falls back to `ssh_user`) |
| `bastion_private_key` | String | - | SSH private key for bastion (sensitive) |
| `bastion_key_path` | String | - | Path to SSH key for bastion |
| `bastion_password` | String | - | SSH password for bastion (sensitive) |
| `owner` | String | `"root"` | File owner on remote |
| `group` | String | `"root"` | File group on remote |
| `mode` | String | `"0644"` | File permissions in octal |

> Note: Authentication options are mutually exclusive. Provider-level defaults are used when resource-level values are not specified.

### Computed Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | String | Resource identifier (`host:destination`) |
| `source_hash` | String | SHA256 hash of source file (`sha256:...`) |
| `size` | Number | File size in bytes |

### Import

Import existing remote files using the format `host:destination`:

```bash
terraform import filesync_file.config "192.168.1.100:/etc/myapp/config.json"
```

## Resource: filesync_directory

Manages synchronization of an entire directory to a remote host via SSH/SFTP.

### Example

```hcl
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
```

### Required Arguments for filesync_directory

| Argument | Type | Description |
|----------|------|-------------|
| `source` | String | Local directory path to sync |
| `destination` | String | Remote absolute path on target host |
| `host` | String | Remote host address (IP or hostname) |

### Optional Arguments for filesync_directory

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ssh_user` | String | `"root"` | SSH username |
| `ssh_private_key` | String | - | SSH private key content (sensitive) |
| `ssh_key_path` | String | - | Path to SSH private key file |
| `ssh_port` | Number | `22` | SSH port |
| `ssh_password` | String | - | SSH password for password auth (sensitive) |
| `ssh_certificate` | String | - | SSH certificate content (sensitive) |
| `ssh_certificate_path` | String | - | Path to SSH certificate file |
| `bastion_host` | String | - | Bastion/jump host address for multi-hop SSH |
| `bastion_port` | Number | `22` | Bastion host SSH port |
| `bastion_user` | String | - | SSH user for bastion (falls back to `ssh_user`) |
| `bastion_private_key` | String | - | SSH private key for bastion (sensitive) |
| `bastion_key_path` | String | - | Path to SSH key for bastion |
| `bastion_password` | String | - | SSH password for bastion (sensitive) |
| `owner` | String | `"root"` | File owner on remote |
| `group` | String | `"root"` | File group on remote |
| `mode` | String | `"0644"` | File permissions in octal |
| `exclude` | List | `[]` | Glob patterns to exclude (e.g., `"*.tmp"`, `".git"`) |

### Computed Attributes for filesync_directory

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | String | Resource identifier (`host:destination`) |
| `source_hash` | String | Combined SHA256 hash of all files |
| `file_count` | Number | Number of files synced |
| `total_size` | Number | Total size of all files in bytes |
| `file_hashes` | Map | Map of relative paths to their SHA256 hashes |

### Behavior

- Only uploads files that have changed (based on hash comparison)
- Automatically creates destination directory structure
- Removes remote files that no longer exist locally
- Supports glob patterns for excluding files

## Provider Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `ssh_user` | String | Default SSH username for all resources |
| `ssh_private_key` | String | Default SSH private key content (sensitive) |
| `ssh_key_path` | String | Default path to SSH private key file |
| `ssh_port` | Number | Default SSH port for all resources |
| `ssh_password` | String | Default SSH password for password authentication (sensitive) |
| `ssh_certificate` | String | Default SSH certificate content for certificate auth (sensitive) |
| `ssh_certificate_path` | String | Default path to SSH certificate file |
| `bastion_host` | String | Default bastion/jump host address |
| `bastion_port` | Number | Default bastion host SSH port |
| `bastion_user` | String | Default SSH user for bastion host |
| `bastion_private_key` | String | Default SSH private key for bastion (sensitive) |
| `bastion_key_path` | String | Default path to SSH key for bastion |
| `bastion_password` | String | Default SSH password for bastion (sensitive) |

## SSH Authentication

The provider supports three authentication methods:

### Private Key Authentication (Default)

```hcl
provider "filesync" {
  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/id_ed25519"
}

# Or inline key:
provider "filesync" {
  ssh_user        = "deploy"
  ssh_private_key = var.ssh_private_key
}
```

### Password Authentication

```hcl
provider "filesync" {
  ssh_user     = "admin"
  ssh_password = var.ssh_password
}
```

### Certificate Authentication

SSH certificates are signed by a Certificate Authority (CA) and provide stronger authentication than plain keys.

```hcl
provider "filesync" {
  ssh_user             = "deploy"
  ssh_key_path         = "~/.ssh/id_ed25519"
  ssh_certificate_path = "~/.ssh/id_ed25519-cert.pub"
}
```

Authentication method is automatically inferred from the provided credentials:

- If `ssh_password` is set → password authentication
- If `ssh_certificate` or `ssh_certificate_path` is set → certificate authentication
- Otherwise → private key authentication

### Bastion/Jump Host (Multi-hop SSH)

When targets are only reachable through a bastion host, configure the jump host settings:

```hcl
provider "filesync" {
  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/deploy_key"

  # Bastion host configuration
  bastion_host     = "bastion.example.com"
  bastion_user     = "jumpuser"
  bastion_key_path = "~/.ssh/bastion_key"
}

resource "filesync_file" "internal_config" {
  source      = "./config.json"
  destination = "/etc/app/config.json"
  host        = "10.0.0.50"  # Internal host only reachable via bastion
  mode        = "0644"
}
```

You can also configure bastion settings per-resource to use different jump hosts:

```hcl
resource "filesync_file" "prod_config" {
  source      = "./config.json"
  destination = "/etc/app/config.json"
  host        = "10.0.1.100"

  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/deploy_key"

  # Per-resource bastion configuration
  bastion_host     = "prod-bastion.example.com"
  bastion_user     = "jump"
  bastion_key_path = "~/.ssh/prod_bastion_key"
}
```

Bastion authentication supports the same methods as target authentication:

- Private key (inline or file path)
- Password authentication
- Falls back to target credentials if bastion-specific credentials aren't set

## Data Source: filesync_host

Defines a reusable host configuration for file synchronization. This is useful when managing files on multiple hosts with different credentials.

```hcl
data "filesync_host" "webserver" {
  address      = "192.168.1.100"
  ssh_user     = "deploy"
  ssh_key_path = "~/.ssh/deploy_key"
}

data "filesync_host" "database" {
  address      = "192.168.1.101"
  ssh_user     = "admin"
  ssh_password = var.db_ssh_password
}

resource "filesync_file" "nginx_config" {
  source      = "${path.module}/configs/nginx.conf"
  destination = "/etc/nginx/nginx.conf"
  host        = data.filesync_host.webserver.address

  ssh_user     = data.filesync_host.webserver.ssh_user
  ssh_key_path = data.filesync_host.webserver.ssh_key_path
  mode         = "0644"
}
```

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `address` | String | Host address (IP or hostname) - **required** |
| `ssh_user` | String | SSH username |
| `ssh_private_key` | String | SSH private key content (sensitive) |
| `ssh_key_path` | String | Path to SSH private key file |
| `ssh_port` | Number | SSH port |
| `ssh_password` | String | SSH password (sensitive) |
| `ssh_certificate` | String | SSH certificate content (sensitive) |
| `ssh_certificate_path` | String | Path to SSH certificate file |

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | String | Unique identifier for this host configuration |

## Drift Detection

The provider implements intelligent drift detection:

**During `terraform plan`:**

- Compares local file hash against state (instant, no remote connection)
- Shows "will update" if local file changed

**During `terraform apply`:**

- Connects to remote and calculates current remote hash
- Compares remote hash with state
- If drift detected, fails with detailed error and resolution options

Example drift error:

```text
Error: Remote file drift detected

  Resource: filesync_file.config
  File: /etc/myapp/app.conf

  Expected (from state): sha256:abc123...
  Found (on remote):     sha256:def456...

  To resolve:
    - terraform refresh          # Accept remote as source of truth
    - terraform apply -replace   # Force overwrite remote
```

## Development

### Prerequisites

- Go 1.24+
- [Task](https://taskfile.dev/) (optional, for build automation)
- Terraform 1.0+ or OpenTofu

### Build Commands

```bash
# Build provider binary
task build

# Install locally for testing
task install

# Full dev workflow: deps → build → install
task dev

# Run unit tests
task test

# Run acceptance tests (requires real SSH target)
TF_ACC=1 task testacc

# Format code
task fmt

# Run linter
task lint

# Generate documentation
task docs

# Run example configuration
task example

# Generate code coverage report
task coverage

# View coverage in browser
task coverage:view

# Get coverage percentage (for badges)
task coverage:badge
```

### Code Coverage

Run tests with coverage collection:

```bash
task coverage
```

This generates:

- `coverage/coverage.out` - Raw coverage data
- `coverage/coverage.html` - Interactive HTML report

View the HTML report in your browser with `task coverage:view`.

### Project Structure

```text
terraform-provider-filesync/
├── main.go                    # Provider entry point
├── go.mod                     # Go module definition
├── Taskfile.yml               # Build automation
├── internal/
│   ├── provider/
│   │   ├── provider.go        # Provider configuration
│   │   └── file_resource.go   # filesync_file resource
│   └── ssh/
│       └── client.go          # SSH/SFTP client
└── examples/
    └── basic/main.tf          # Usage example
```

## Roadmap

- [x] `filesync_directory` resource for bulk sync
- [x] Support for password authentication
- [x] Support for certificate authentication
- [x] `filesync_host` data source for reusable host configs
- [x] Content diff on drift detection
- [x] Bastion/jump host support for multi-hop SSH
- [ ] Retry logic for transient SSH failures
- [ ] Proper host key verification (currently uses InsecureIgnoreHostKey)
- [ ] File backup before overwrite option

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
