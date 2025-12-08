package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// AbsolutePathValidator validates that a string is an absolute path.
type absolutePathValidator struct{}

func (v absolutePathValidator) Description(_ context.Context) string {
	return "value must be an absolute path starting with '/'"
}

func (v absolutePathValidator) MarkdownDescription(_ context.Context) string {
	return "value must be an absolute path starting with `/`"
}

func (v absolutePathValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()
	if !strings.HasPrefix(value, "/") {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Absolute Path",
			fmt.Sprintf("Path must be an absolute path starting with '/'. Got: %s", value),
		)
	}
}

// AbsolutePath returns a validator that checks if a path is absolute.
func AbsolutePath() validator.String {
	return absolutePathValidator{}
}

// OctalModeValidator validates that a string is a valid octal file mode.
type octalModeValidator struct{}

var validModeRegex = regexp.MustCompile(`^[0-7]{3,4}$`)

func (v octalModeValidator) Description(_ context.Context) string {
	return "value must be a valid octal file mode (3-4 digits, e.g., '644' or '0755')"
}

func (v octalModeValidator) MarkdownDescription(_ context.Context) string {
	return "value must be a valid octal file mode (3-4 digits, e.g., `644` or `0755`)"
}

func (v octalModeValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()
	if value == "" {
		return // Empty is allowed (uses default)
	}

	if !validModeRegex.MatchString(value) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid File Mode",
			fmt.Sprintf("Mode must be 3-4 octal digits (0-7). Examples: '644', '0755', '0600'. Got: %s", value),
		)
	}
}

// OctalMode returns a validator that checks if a mode string is valid octal.
func OctalMode() validator.String {
	return octalModeValidator{}
}

// UnixNameValidator validates that a string is a valid Unix user/group name.
type unixNameValidator struct {
	fieldType string // "owner" or "group"
}

var validUnixNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$|^[0-9]+$`)

func (v unixNameValidator) Description(_ context.Context) string {
	return fmt.Sprintf("value must be a valid Unix %s name or numeric ID", v.fieldType)
}

func (v unixNameValidator) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("value must be a valid Unix %s name or numeric ID", v.fieldType)
}

func (v unixNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()
	if value == "" {
		return // Empty is allowed
	}

	if len(value) > 32 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			fmt.Sprintf("Invalid %s Name", v.fieldType),
			fmt.Sprintf("%s name is too long (max 32 characters). Got: %d characters", v.fieldType, len(value)),
		)
		return
	}

	if !validUnixNameRegex.MatchString(value) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			fmt.Sprintf("Invalid %s Name", v.fieldType),
			fmt.Sprintf("%s must be a valid Unix name (alphanumeric, underscore, hyphen, or numeric). Got: %s", v.fieldType, value),
		)
	}
}

// UnixOwner returns a validator for Unix owner names.
func UnixOwner() validator.String {
	return unixNameValidator{fieldType: "owner"}
}

// UnixGroup returns a validator for Unix group names.
func UnixGroup() validator.String {
	return unixNameValidator{fieldType: "group"}
}

// MutuallyExclusiveWith returns validators for mutually exclusive attributes.
// This is a convenience wrapper around stringvalidator.ConflictsWith.
func MutuallyExclusiveWith(expressions ...path.Expression) validator.String {
	return stringvalidator.ConflictsWith(expressions...)
}
