package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAbsolutePath_Description tests the Description method.
func TestAbsolutePath_Description(t *testing.T) {
	validator := AbsolutePath()
	desc := validator.Description(context.Background())
	assert.Equal(t, "value must be an absolute path starting with '/'", desc)
}

// TestAbsolutePath_MarkdownDescription tests the MarkdownDescription method.
func TestAbsolutePath_MarkdownDescription(t *testing.T) {
	validator := AbsolutePath()
	mdDesc := validator.MarkdownDescription(context.Background())
	assert.Equal(t, "value must be an absolute path starting with `/`", mdDesc)
}

// TestAbsolutePath_ValidateString tests the ValidateString method.
func TestAbsolutePath_ValidateString(t *testing.T) {
	tests := []struct {
		name      string
		value     types.String
		wantError bool
		errCount  int
	}{
		{
			name:      "valid absolute path",
			value:     types.StringValue("/etc/config"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid root path",
			value:     types.StringValue("/"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid nested path",
			value:     types.StringValue("/usr/local/bin"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "relative path",
			value:     types.StringValue("relative/path"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "relative path with dot",
			value:     types.StringValue("./relative"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "relative path with parent",
			value:     types.StringValue("../parent"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "null value",
			value:     types.StringNull(),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "unknown value",
			value:     types.StringUnknown(),
			wantError: false,
			errCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := AbsolutePath()
			req := validator.StringRequest{
				Path:        path.Root("test"),
				ConfigValue: tt.value,
			}
			resp := &validator.StringResponse{}

			v.ValidateString(context.Background(), req, resp)

			if tt.wantError {
				assert.True(t, resp.Diagnostics.HasError(), "expected error but got none")
				assert.Equal(t, tt.errCount, len(resp.Diagnostics.Errors()))
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "unexpected error: %v", resp.Diagnostics.Errors())
			}
		})
	}
}

// TestOctalMode_Description tests the Description method.
func TestOctalMode_Description(t *testing.T) {
	validator := OctalMode()
	desc := validator.Description(context.Background())
	assert.Equal(t, "value must be a valid octal file mode (3-4 digits, e.g., '644' or '0755')", desc)
}

// TestOctalMode_MarkdownDescription tests the MarkdownDescription method.
func TestOctalMode_MarkdownDescription(t *testing.T) {
	validator := OctalMode()
	mdDesc := validator.MarkdownDescription(context.Background())
	assert.Equal(t, "value must be a valid octal file mode (3-4 digits, e.g., `644` or `0755`)", mdDesc)
}

// TestOctalMode_ValidateString tests the ValidateString method.
func TestOctalMode_ValidateString(t *testing.T) {
	tests := []struct {
		name      string
		value     types.String
		wantError bool
		errCount  int
	}{
		{
			name:      "valid 3-digit octal",
			value:     types.StringValue("644"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid 4-digit octal",
			value:     types.StringValue("0755"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid 4-digit octal 0644",
			value:     types.StringValue("0644"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid restrictive mode",
			value:     types.StringValue("600"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid permissive mode",
			value:     types.StringValue("777"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "invalid - 2 digits",
			value:     types.StringValue("64"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "invalid - 5 digits",
			value:     types.StringValue("07777"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "invalid - contains non-octal",
			value:     types.StringValue("888"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "invalid - contains letters",
			value:     types.StringValue("abc"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "empty string",
			value:     types.StringValue(""),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "null value",
			value:     types.StringNull(),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "unknown value",
			value:     types.StringUnknown(),
			wantError: false,
			errCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := OctalMode()
			req := validator.StringRequest{
				Path:        path.Root("mode"),
				ConfigValue: tt.value,
			}
			resp := &validator.StringResponse{}

			v.ValidateString(context.Background(), req, resp)

			if tt.wantError {
				assert.True(t, resp.Diagnostics.HasError(), "expected error but got none")
				assert.Equal(t, tt.errCount, len(resp.Diagnostics.Errors()))
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "unexpected error: %v", resp.Diagnostics.Errors())
			}
		})
	}
}

// TestUnixOwner_Description tests the Description method.
func TestUnixOwner_Description(t *testing.T) {
	validator := UnixOwner()
	desc := validator.Description(context.Background())
	assert.Equal(t, "value must be a valid Unix owner name or numeric ID", desc)
}

// TestUnixOwner_MarkdownDescription tests the MarkdownDescription method.
func TestUnixOwner_MarkdownDescription(t *testing.T) {
	validator := UnixOwner()
	mdDesc := validator.MarkdownDescription(context.Background())
	assert.Equal(t, "value must be a valid Unix owner name or numeric ID", mdDesc)
}

// TestUnixOwner_ValidateString tests the ValidateString method.
func TestUnixOwner_ValidateString(t *testing.T) {
	tests := []struct {
		name      string
		value     types.String
		wantError bool
		errCount  int
	}{
		{
			name:      "valid user name",
			value:     types.StringValue("root"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid user name with underscore",
			value:     types.StringValue("http_user"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid user name with hyphen",
			value:     types.StringValue("my-user"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid numeric ID",
			value:     types.StringValue("1000"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid numeric ID zero",
			value:     types.StringValue("0"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "invalid - name starts with number",
			value:     types.StringValue("1user"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "invalid - name too long",
			value:     types.StringValue("this_is_a_very_long_unix_user_name_exceed"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "invalid - contains special chars",
			value:     types.StringValue("user@host"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "invalid - contains space",
			value:     types.StringValue("user name"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "empty string",
			value:     types.StringValue(""),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "null value",
			value:     types.StringNull(),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "unknown value",
			value:     types.StringUnknown(),
			wantError: false,
			errCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := UnixOwner()
			req := validator.StringRequest{
				Path:        path.Root("owner"),
				ConfigValue: tt.value,
			}
			resp := &validator.StringResponse{}

			v.ValidateString(context.Background(), req, resp)

			if tt.wantError {
				assert.True(t, resp.Diagnostics.HasError(), "expected error but got none")
				assert.Equal(t, tt.errCount, len(resp.Diagnostics.Errors()))
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "unexpected error: %v", resp.Diagnostics.Errors())
			}
		})
	}
}

// TestUnixGroup_Description tests the Description method.
func TestUnixGroup_Description(t *testing.T) {
	v := UnixGroup()
	desc := v.Description(context.Background())
	assert.Equal(t, "value must be a valid Unix group name or numeric ID", desc)
}

// TestUnixGroup_MarkdownDescription tests the MarkdownDescription method.
func TestUnixGroup_MarkdownDescription(t *testing.T) {
	v := UnixGroup()
	mdDesc := v.MarkdownDescription(context.Background())
	assert.Equal(t, "value must be a valid Unix group name or numeric ID", mdDesc)
}

// TestUnixGroup_ValidateString tests the ValidateString method for group names.
func TestUnixGroup_ValidateString(t *testing.T) {
	tests := []struct {
		name      string
		value     types.String
		wantError bool
		errCount  int
	}{
		{
			name:      "valid group name",
			value:     types.StringValue("wheel"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid group name with underscore",
			value:     types.StringValue("http_group"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid group name with hyphen",
			value:     types.StringValue("my-group"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "valid numeric group ID",
			value:     types.StringValue("1000"),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "invalid - group name starts with number",
			value:     types.StringValue("1group"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "invalid - group name too long",
			value:     types.StringValue("this_is_a_very_long_unix_group_name_exceed"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "invalid - contains special chars",
			value:     types.StringValue("group!"),
			wantError: true,
			errCount:  1,
		},
		{
			name:      "empty string",
			value:     types.StringValue(""),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "null value",
			value:     types.StringNull(),
			wantError: false,
			errCount:  0,
		},
		{
			name:      "unknown value",
			value:     types.StringUnknown(),
			wantError: false,
			errCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := UnixGroup()
			req := validator.StringRequest{
				Path:        path.Root("group"),
				ConfigValue: tt.value,
			}
			resp := &validator.StringResponse{}

			v.ValidateString(context.Background(), req, resp)

			if tt.wantError {
				assert.True(t, resp.Diagnostics.HasError(), "expected error but got none")
				assert.Equal(t, tt.errCount, len(resp.Diagnostics.Errors()))
			} else {
				assert.False(t, resp.Diagnostics.HasError(), "unexpected error: %v", resp.Diagnostics.Errors())
			}
		})
	}
}

// TestMutuallyExclusiveWith tests that MutuallyExclusiveWith returns a validator.
func TestMutuallyExclusiveWith(t *testing.T) {
	v := MutuallyExclusiveWith(path.MatchRoot("field1"), path.MatchRoot("field2"))
	require.NotNil(t, v)
	// Just verify it returns a non-nil validator
	desc := v.Description(context.Background())
	assert.NotEmpty(t, desc)
}
