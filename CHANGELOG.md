# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial release of `terraform-provider-filesync`.
- `filesync_file` resource for managing individual files via SSH/SFTP.
- `filesync_directory` resource for managing directory synchronization.
- Drift detection for files modified outside of Terraform.
- Support for multiple SSH authentication methods (private key, password, certificate, bastion).
