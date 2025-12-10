package provider

import (
	"os"
	"path/filepath"

	"github.com/darshan-rambhia/gosftp"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// SSHConfigurable is an interface for resources that can be configured with SSH settings.
// Both FileResourceModel and DirectoryResourceModel implement this interface.
type SSHConfigurable interface {
	GetHost() types.String
	GetSSHPort() types.Int64
	GetSSHUser() types.String
	GetSSHPassword() types.String
	GetSSHPrivateKey() types.String
	GetSSHKeyPath() types.String
	GetSSHCertificate() types.String
	GetSSHCertificatePath() types.String
	GetBastionHost() types.String
	GetBastionPort() types.Int64
	GetBastionUser() types.String
	GetBastionKey() types.String
	GetBastionKeyPath() types.String
	GetBastionPassword() types.String
	GetInsecureIgnoreHostKey() types.Bool
	GetKnownHostsFile() types.String
	GetStrictHostKeyChecking() types.String
}

// Implement SSHConfigurable for FileResourceModel.
func (m *FileResourceModel) GetHost() types.String                { return m.Host }
func (m *FileResourceModel) GetSSHPort() types.Int64              { return m.SSHPort }
func (m *FileResourceModel) GetSSHUser() types.String             { return m.SSHUser }
func (m *FileResourceModel) GetSSHPassword() types.String         { return m.SSHPassword }
func (m *FileResourceModel) GetSSHPrivateKey() types.String       { return m.SSHPrivateKey }
func (m *FileResourceModel) GetSSHKeyPath() types.String          { return m.SSHKeyPath }
func (m *FileResourceModel) GetSSHCertificate() types.String      { return m.SSHCertificate }
func (m *FileResourceModel) GetSSHCertificatePath() types.String  { return m.SSHCertificatePath }
func (m *FileResourceModel) GetBastionHost() types.String         { return m.BastionHost }
func (m *FileResourceModel) GetBastionPort() types.Int64          { return m.BastionPort }
func (m *FileResourceModel) GetBastionUser() types.String         { return m.BastionUser }
func (m *FileResourceModel) GetBastionKey() types.String          { return m.BastionKey }
func (m *FileResourceModel) GetBastionKeyPath() types.String      { return m.BastionKeyPath }
func (m *FileResourceModel) GetBastionPassword() types.String     { return m.BastionPassword }
func (m *FileResourceModel) GetInsecureIgnoreHostKey() types.Bool  { return m.InsecureIgnoreHostKey }
func (m *FileResourceModel) GetKnownHostsFile() types.String       { return m.KnownHostsFile }
func (m *FileResourceModel) GetStrictHostKeyChecking() types.String { return m.StrictHostKeyChecking }

// Implement SSHConfigurable for DirectoryResourceModel.
func (m *DirectoryResourceModel) GetHost() types.String               { return m.Host }
func (m *DirectoryResourceModel) GetSSHPort() types.Int64             { return m.SSHPort }
func (m *DirectoryResourceModel) GetSSHUser() types.String            { return m.SSHUser }
func (m *DirectoryResourceModel) GetSSHPassword() types.String        { return m.SSHPassword }
func (m *DirectoryResourceModel) GetSSHPrivateKey() types.String      { return m.SSHPrivateKey }
func (m *DirectoryResourceModel) GetSSHKeyPath() types.String         { return m.SSHKeyPath }
func (m *DirectoryResourceModel) GetSSHCertificate() types.String     { return m.SSHCertificate }
func (m *DirectoryResourceModel) GetSSHCertificatePath() types.String { return m.SSHCertificatePath }
func (m *DirectoryResourceModel) GetBastionHost() types.String        { return m.BastionHost }
func (m *DirectoryResourceModel) GetBastionPort() types.Int64         { return m.BastionPort }
func (m *DirectoryResourceModel) GetBastionUser() types.String        { return m.BastionUser }
func (m *DirectoryResourceModel) GetBastionKey() types.String         { return m.BastionKey }
func (m *DirectoryResourceModel) GetBastionKeyPath() types.String     { return m.BastionKeyPath }
func (m *DirectoryResourceModel) GetBastionPassword() types.String    { return m.BastionPassword }
func (m *DirectoryResourceModel) GetInsecureIgnoreHostKey() types.Bool {
	return m.InsecureIgnoreHostKey
}
func (m *DirectoryResourceModel) GetKnownHostsFile() types.String        { return m.KnownHostsFile }
func (m *DirectoryResourceModel) GetStrictHostKeyChecking() types.String { return m.StrictHostKeyChecking }

// BuildSSHConfig creates an gosftp.Config from resource data and provider config.
func BuildSSHConfig(data SSHConfigurable, providerConfig *FilesyncProviderModel) gosftp.Config {
	config := gosftp.Config{
		Host: data.GetHost().ValueString(),
		Port: int(data.GetSSHPort().ValueInt64()),
		User: data.GetSSHUser().ValueString(),
	}

	// Determine SSH credentials - resource values override provider defaults.
	// Check password authentication.
	if !data.GetSSHPassword().IsNull() && data.GetSSHPassword().ValueString() != "" {
		config.Password = data.GetSSHPassword().ValueString()
	} else if providerConfig != nil && !providerConfig.SSHPassword.IsNull() {
		config.Password = providerConfig.SSHPassword.ValueString()
	}

	// Check private key authentication.
	if !data.GetSSHPrivateKey().IsNull() && data.GetSSHPrivateKey().ValueString() != "" {
		config.PrivateKey = data.GetSSHPrivateKey().ValueString()
	} else if !data.GetSSHKeyPath().IsNull() && data.GetSSHKeyPath().ValueString() != "" {
		config.KeyPath = ExpandPath(data.GetSSHKeyPath().ValueString())
	} else if providerConfig != nil {
		if !providerConfig.SSHPrivateKey.IsNull() && providerConfig.SSHPrivateKey.ValueString() != "" {
			config.PrivateKey = providerConfig.SSHPrivateKey.ValueString()
		} else if !providerConfig.SSHKeyPath.IsNull() && providerConfig.SSHKeyPath.ValueString() != "" {
			config.KeyPath = ExpandPath(providerConfig.SSHKeyPath.ValueString())
		}
	}

	// Check certificate authentication.
	if !data.GetSSHCertificate().IsNull() && data.GetSSHCertificate().ValueString() != "" {
		config.Certificate = data.GetSSHCertificate().ValueString()
	} else if !data.GetSSHCertificatePath().IsNull() && data.GetSSHCertificatePath().ValueString() != "" {
		config.CertificatePath = ExpandPath(data.GetSSHCertificatePath().ValueString())
	} else if providerConfig != nil {
		if !providerConfig.SSHCertificate.IsNull() && providerConfig.SSHCertificate.ValueString() != "" {
			config.Certificate = providerConfig.SSHCertificate.ValueString()
		} else if !providerConfig.SSHCertificatePath.IsNull() && providerConfig.SSHCertificatePath.ValueString() != "" {
			config.CertificatePath = ExpandPath(providerConfig.SSHCertificatePath.ValueString())
		}
	}

	// Check bastion/jump host configuration.
	if !data.GetBastionHost().IsNull() && data.GetBastionHost().ValueString() != "" {
		config.BastionHost = data.GetBastionHost().ValueString()
		if !data.GetBastionPort().IsNull() {
			config.BastionPort = int(data.GetBastionPort().ValueInt64())
		}
		if !data.GetBastionUser().IsNull() && data.GetBastionUser().ValueString() != "" {
			config.BastionUser = data.GetBastionUser().ValueString()
		}
		if !data.GetBastionKey().IsNull() && data.GetBastionKey().ValueString() != "" {
			config.BastionKey = data.GetBastionKey().ValueString()
		} else if !data.GetBastionKeyPath().IsNull() && data.GetBastionKeyPath().ValueString() != "" {
			config.BastionKeyPath = ExpandPath(data.GetBastionKeyPath().ValueString())
		}
		if !data.GetBastionPassword().IsNull() && data.GetBastionPassword().ValueString() != "" {
			config.BastionPassword = data.GetBastionPassword().ValueString()
		}
	} else if providerConfig != nil && !providerConfig.BastionHost.IsNull() && providerConfig.BastionHost.ValueString() != "" {
		// Fall back to provider config for bastion.
		config.BastionHost = providerConfig.BastionHost.ValueString()
		if !providerConfig.BastionPort.IsNull() {
			config.BastionPort = int(providerConfig.BastionPort.ValueInt64())
		}
		if !providerConfig.BastionUser.IsNull() && providerConfig.BastionUser.ValueString() != "" {
			config.BastionUser = providerConfig.BastionUser.ValueString()
		}
		if !providerConfig.BastionKey.IsNull() && providerConfig.BastionKey.ValueString() != "" {
			config.BastionKey = providerConfig.BastionKey.ValueString()
		} else if !providerConfig.BastionKeyPath.IsNull() && providerConfig.BastionKeyPath.ValueString() != "" {
			config.BastionKeyPath = ExpandPath(providerConfig.BastionKeyPath.ValueString())
		}
		if !providerConfig.BastionPassword.IsNull() && providerConfig.BastionPassword.ValueString() != "" {
			config.BastionPassword = providerConfig.BastionPassword.ValueString()
		}
	}

	// Check insecure host key setting.
	// Resource-level setting takes precedence over provider-level if explicitly set.
	if !data.GetInsecureIgnoreHostKey().IsNull() {
		// Resource explicitly set this value (true or false), use it.
		config.InsecureIgnoreHostKey = data.GetInsecureIgnoreHostKey().ValueBool()
	} else if providerConfig != nil && !providerConfig.InsecureIgnoreHostKey.IsNull() {
		// Resource didn't set it, fall back to provider-level setting.
		config.InsecureIgnoreHostKey = providerConfig.InsecureIgnoreHostKey.ValueBool()
	}

	// Check known_hosts_file setting.
	// Resource-level setting takes precedence over provider-level if set.
	if !data.GetKnownHostsFile().IsNull() && data.GetKnownHostsFile().ValueString() != "" {
		config.KnownHostsFile = ExpandPath(data.GetKnownHostsFile().ValueString())
	} else if providerConfig != nil && !providerConfig.KnownHostsFile.IsNull() && providerConfig.KnownHostsFile.ValueString() != "" {
		config.KnownHostsFile = ExpandPath(providerConfig.KnownHostsFile.ValueString())
	}

	// Check strict_host_key_checking setting.
	// Resource-level setting takes precedence over provider-level if set.
	// Valid values: "yes", "no", "accept-new"
	if !data.GetStrictHostKeyChecking().IsNull() && data.GetStrictHostKeyChecking().ValueString() != "" {
		config.StrictHostKeyChecking = gosftp.StrictHostKeyChecking(data.GetStrictHostKeyChecking().ValueString())
	} else if providerConfig != nil && !providerConfig.StrictHostKeyChecking.IsNull() && providerConfig.StrictHostKeyChecking.ValueString() != "" {
		config.StrictHostKeyChecking = gosftp.StrictHostKeyChecking(providerConfig.StrictHostKeyChecking.ValueString())
	}

	return config
}

// ExpandPath expands ~ to home directory.
func ExpandPath(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[1:])
	}
	return path
}
