package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories are used to instantiate a provider during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can.
// reattach.
//
// Note: Full acceptance tests have been moved to tests/acceptance/ package.
// which treats the provider as an external package like real Terraform usage.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"filesync": providerserver.NewProtocol6WithError(New("test")()),
}
