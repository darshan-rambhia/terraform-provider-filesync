# Basic Example

This example demonstrates basic usage of the `filesync` provider to sync files to a remote host.

## Prerequisites

1. **SSH access** to a remote host
2. **SSH key** configured for authentication
3. **Provider installed** locally (`task dev` from repo root)

## Setup

1. Create the files directory with your config files:

   ```bash
   mkdir -p files
   echo "# nginx config" > files/nginx.conf
   echo "# docker compose" > files/docker-compose.yml
   echo "SECRET=value" > files/.env
   ```

2. Update `main.tf` with your settings:
   - Change `host` to your target IP/hostname
   - Update `ssh_key_path` to your SSH key location
   - Adjust `ssh_user` if needed

3. Initialize and apply:

   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

## Files

| File | Description |
|------|-------------|
| `main.tf` | Provider and resource configuration |
| `files/` | Local files to sync (create this directory) |

## Notes

- The `files/` directory is not committed to git (add your own files)
- This example uses a local provider installation - run `task dev` first
- For production, use the provider from the Terraform Registry
