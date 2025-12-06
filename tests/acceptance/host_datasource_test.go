package acceptance

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccHostDataSource_Basic(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.HostDataSourceConfig("test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.filesync_host.test", "address", container.Host),
					resource.TestCheckResourceAttr("data.filesync_host.test", "ssh_user", container.User),
					resource.TestCheckResourceAttr("data.filesync_host.test", "ssh_port", fmt.Sprintf("%d", container.Port)),
					resource.TestCheckResourceAttrSet("data.filesync_host.test", "id"),
				),
			},
		},
	})
}

func TestAccHostDataSource_WithFile(t *testing.T) {
	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)
	sourceFile := CreateTestSourceFile(t, "host datasource file test\n")
	remotePath := "/tmp/test-host-datasource.txt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.HostDataSourceWithFileConfig(sourceFile, remotePath),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.filesync_host.test", "address", container.Host),
					resource.TestCheckResourceAttr("filesync_file.test", "destination", remotePath),
					CheckRemoteFileExists(container, remotePath),
				),
			},
		},
	})
}

func TestAccHostDataSource_ForEach(t *testing.T) {
	// Skip: terraform-plugin-testing framework doesn't support for_each resources.
	// The framework fails with "unexpected index type (string)" when trying to
	// introspect state containing for_each resources.
	t.Skip("terraform-plugin-testing doesn't support for_each resources")

	t.Parallel()

	container := SetupSSHContainer(t)
	cfg := NewTestSSHConfig(container)
	sourceFile := CreateTestSourceFile(t, "foreach test content\n")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg.HostDataSourceForEachConfig(sourceFile),
				Check: resource.ComposeAggregateTestCheckFunc(
					CheckRemoteFileExists(container, "/tmp/server1.txt"),
					CheckRemoteFileExists(container, "/tmp/server2.txt"),
				),
			},
		},
	})
}
