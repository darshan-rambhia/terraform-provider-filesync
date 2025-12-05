package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Helper function to build HostDataSourceModel terraform value.
func buildHostDataSourceTerraformValue(t *testing.T, s schema.Schema, data HostDataSourceModel) tftypes.Value {
	t.Helper()

	strVal := func(s types.String) interface{} {
		if s.IsNull() || s.IsUnknown() {
			return nil
		}
		return s.ValueString()
	}

	int64Val := func(i types.Int64) interface{} {
		if i.IsNull() || i.IsUnknown() {
			return nil
		}
		return i.ValueInt64()
	}

	return tftypes.NewValue(
		s.Type().TerraformType(context.Background()),
		map[string]tftypes.Value{
			"address":              tftypes.NewValue(tftypes.String, strVal(data.Address)),
			"ssh_user":             tftypes.NewValue(tftypes.String, strVal(data.SSHUser)),
			"ssh_private_key":      tftypes.NewValue(tftypes.String, strVal(data.SSHPrivateKey)),
			"ssh_key_path":         tftypes.NewValue(tftypes.String, strVal(data.SSHKeyPath)),
			"ssh_port":             tftypes.NewValue(tftypes.Number, int64Val(data.SSHPort)),
			"ssh_password":         tftypes.NewValue(tftypes.String, strVal(data.SSHPassword)),
			"ssh_certificate":      tftypes.NewValue(tftypes.String, strVal(data.SSHCertificate)),
			"ssh_certificate_path": tftypes.NewValue(tftypes.String, strVal(data.SSHCertificatePath)),
			"id":                   tftypes.NewValue(tftypes.String, strVal(data.ID)),
		},
	)
}

// TestHostDataSource_Read_Success tests successful data source read.
func TestHostDataSource_Read_Success(t *testing.T) {
	d := &HostDataSource{}

	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)

	data := HostDataSourceModel{
		Address:    types.StringValue("192.168.1.100"),
		SSHUser:    types.StringValue("deploy"),
		SSHKeyPath: types.StringValue("~/.ssh/id_rsa"),
		SSHPort:    types.Int64Value(22),
	}

	config := tfsdk.Config{
		Schema: schemaResp.Schema,
		Raw:    buildHostDataSourceTerraformValue(t, schemaResp.Schema, data),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
	}

	resp := &datasource.ReadResponse{
		State: state,
	}

	d.Read(context.Background(), datasource.ReadRequest{
		Config: config,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
	}

	// Verify the ID was set.
	var resultData HostDataSourceModel
	resp.State.Get(context.Background(), &resultData)

	expectedID := "host:192.168.1.100"
	if resultData.ID.ValueString() != expectedID {
		t.Errorf("expected ID %q, got %q", expectedID, resultData.ID.ValueString())
	}
}

// TestHostDataSource_Read_WithPassword tests read with password authentication.
func TestHostDataSource_Read_WithPassword(t *testing.T) {
	d := &HostDataSource{}

	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)

	data := HostDataSourceModel{
		Address:     types.StringValue("legacy.example.com"),
		SSHUser:     types.StringValue("admin"),
		SSHPassword: types.StringValue("secret123"),
	}

	config := tfsdk.Config{
		Schema: schemaResp.Schema,
		Raw:    buildHostDataSourceTerraformValue(t, schemaResp.Schema, data),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
	}

	resp := &datasource.ReadResponse{
		State: state,
	}

	d.Read(context.Background(), datasource.ReadRequest{
		Config: config,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
	}

	var resultData HostDataSourceModel
	resp.State.Get(context.Background(), &resultData)

	expectedID := "host:legacy.example.com"
	if resultData.ID.ValueString() != expectedID {
		t.Errorf("expected ID %q, got %q", expectedID, resultData.ID.ValueString())
	}
}

// TestHostDataSource_Read_WithCertificate tests read with certificate authentication.
func TestHostDataSource_Read_WithCertificate(t *testing.T) {
	d := &HostDataSource{}

	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)

	data := HostDataSourceModel{
		Address:            types.StringValue("secure.example.com"),
		SSHUser:            types.StringValue("deploy"),
		SSHKeyPath:         types.StringValue("~/.ssh/id_ed25519"),
		SSHCertificatePath: types.StringValue("~/.ssh/id_ed25519-cert.pub"),
	}

	config := tfsdk.Config{
		Schema: schemaResp.Schema,
		Raw:    buildHostDataSourceTerraformValue(t, schemaResp.Schema, data),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
	}

	resp := &datasource.ReadResponse{
		State: state,
	}

	d.Read(context.Background(), datasource.ReadRequest{
		Config: config,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
	}

	var resultData HostDataSourceModel
	resp.State.Get(context.Background(), &resultData)

	expectedID := "host:secure.example.com"
	if resultData.ID.ValueString() != expectedID {
		t.Errorf("expected ID %q, got %q", expectedID, resultData.ID.ValueString())
	}
}

// TestHostDataSource_Read_MinimalConfig tests read with only address.
func TestHostDataSource_Read_MinimalConfig(t *testing.T) {
	d := &HostDataSource{}

	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)

	data := HostDataSourceModel{
		Address: types.StringValue("10.0.0.1"),
	}

	config := tfsdk.Config{
		Schema: schemaResp.Schema,
		Raw:    buildHostDataSourceTerraformValue(t, schemaResp.Schema, data),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
	}

	resp := &datasource.ReadResponse{
		State: state,
	}

	d.Read(context.Background(), datasource.ReadRequest{
		Config: config,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
	}

	var resultData HostDataSourceModel
	resp.State.Get(context.Background(), &resultData)

	expectedID := "host:10.0.0.1"
	if resultData.ID.ValueString() != expectedID {
		t.Errorf("expected ID %q, got %q", expectedID, resultData.ID.ValueString())
	}
}

// TestHostDataSource_Read_WithInlineKey tests read with inline private key.
func TestHostDataSource_Read_WithInlineKey(t *testing.T) {
	d := &HostDataSource{}

	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)

	data := HostDataSourceModel{
		Address:       types.StringValue("server.example.com"),
		SSHUser:       types.StringValue("deploy"),
		SSHPrivateKey: types.StringValue("-----BEGIN RSA PRIVATE KEY-----\nfake-key-content\n-----END RSA PRIVATE KEY-----"),
		SSHPort:       types.Int64Value(2222),
	}

	config := tfsdk.Config{
		Schema: schemaResp.Schema,
		Raw:    buildHostDataSourceTerraformValue(t, schemaResp.Schema, data),
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
	}

	resp := &datasource.ReadResponse{
		State: state,
	}

	d.Read(context.Background(), datasource.ReadRequest{
		Config: config,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("Read() unexpected error: %v", resp.Diagnostics)
	}

	var resultData HostDataSourceModel
	resp.State.Get(context.Background(), &resultData)

	expectedID := "host:server.example.com"
	if resultData.ID.ValueString() != expectedID {
		t.Errorf("expected ID %q, got %q", expectedID, resultData.ID.ValueString())
	}
}
