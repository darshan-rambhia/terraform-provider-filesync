terraform {
  required_providers {
    filesync = {
      source  = "registry.terraform.io/darshan-rambhia/filesync"
      version = "0.1.0"
    }
  }
}

provider "filesync" {
  ssh_user     = "root"
  ssh_key_path = "~/.ssh/homelab_ed25519"
}

# Example: Sync a single config file
resource "filesync_file" "nginx_config" {
  source      = "${path.module}/files/nginx.conf"
  destination = "/etc/nginx/nginx.conf"
  host        = "192.168.1.100"

  owner = "root"
  group = "root"
  mode  = "0644"
}

# Example: Sync a docker-compose file
resource "filesync_file" "compose" {
  source      = "${path.module}/files/docker-compose.yml"
  destination = "/config/docker-compose.yml"
  host        = "192.168.1.100"

  mode = "0644"
}

# Example: Sync an env file with restricted permissions
resource "filesync_file" "env" {
  source      = "${path.module}/files/.env"
  destination = "/config/.env"
  host        = "192.168.1.100"

  mode = "0600" # Only owner can read
}

# Output the synced file hashes for verification
output "nginx_hash" {
  value = filesync_file.nginx_config.source_hash
}

output "compose_hash" {
  value = filesync_file.compose.source_hash
}
