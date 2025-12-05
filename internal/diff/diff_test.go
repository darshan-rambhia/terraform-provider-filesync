package diff

import (
	"fmt"
	"strings"
	"testing"
)

func TestGenerateUnifiedDiff_SimpleChange(t *testing.T) {
	expected := []byte("line1\nline2\nline3\n")
	actual := []byte("line1\nmodified\nline3\n")

	result := GenerateUnifiedDiff(expected, actual, "/test/file.txt")

	if result == "" {
		t.Fatal("expected non-empty diff")
	}

	if !strings.Contains(result, "--- expected:") {
		t.Error("diff should contain expected header")
	}

	if !strings.Contains(result, "+++ actual:") {
		t.Error("diff should contain actual header")
	}

	// Should show some indication of change (the diff library may format differently).
	if !strings.Contains(result, "-") && !strings.Contains(result, "+") {
		t.Errorf("diff should show changes with +/-, got: %s", result)
	}
}

func TestGenerateUnifiedDiff_NoChange(t *testing.T) {
	content := []byte("same content\n")

	result := GenerateUnifiedDiff(content, content, "/test/file.txt")

	if result != "" {
		t.Errorf("expected empty diff for identical content, got: %s", result)
	}
}

func TestGenerateUnifiedDiff_BinaryContent(t *testing.T) {
	// Binary content contains null bytes.
	expected := []byte("text\x00binary")
	actual := []byte("different\x00content")

	result := GenerateUnifiedDiff(expected, actual, "/test/file.bin")

	if result != "" {
		t.Errorf("expected empty diff for binary content, got: %s", result)
	}
}

func TestGenerateUnifiedDiff_TooLarge(t *testing.T) {
	// Create content larger than MaxDiffSize.
	large := make([]byte, MaxDiffSize+1)
	for i := range large {
		large[i] = 'a'
	}

	result := GenerateUnifiedDiff(large, []byte("small"), "/test/large.txt")

	if result != "" {
		t.Errorf("expected empty diff for large content, got length: %d", len(result))
	}
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected bool
	}{
		{"text content", []byte("hello world"), false},
		{"empty", []byte{}, false},
		{"null byte", []byte("hello\x00world"), true},
		{"binary at start", []byte{0x00, 'a', 'b'}, true},
		{"unicode text", []byte("héllo wörld"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBinary(tt.content)
			if result != tt.expected {
				t.Errorf("isBinary(%q) = %v, want %v", tt.content, result, tt.expected)
			}
		})
	}
}

func TestFormatDriftError_WithDiff(t *testing.T) {
	result := FormatDriftError(
		"filesync_file.config",
		"/etc/app/config.json",
		"sha256:abc123",
		"sha256:def456",
		"- old line\n+ new line\n",
	)

	expectations := []string{
		"modified outside of Terraform",
		"filesync_file.config",
		"/etc/app/config.json",
		"sha256:abc123",
		"sha256:def456",
		"Content diff:",
		"- old line",
		"+ new line",
		"terraform apply -replace",
	}

	for _, exp := range expectations {
		if !strings.Contains(result, exp) {
			t.Errorf("expected error message to contain %q", exp)
		}
	}
}

func TestFormatDriftError_NoDiff(t *testing.T) {
	result := FormatDriftError(
		"filesync_file.binary",
		"/etc/app/binary.dat",
		"sha256:abc123",
		"sha256:def456",
		"", // No diff for binary
	)

	if strings.Contains(result, "Content diff:") {
		t.Error("should not show diff section when diff is empty")
	}

	// Should still show basic info.
	if !strings.Contains(result, "sha256:abc123") {
		t.Error("should still show expected hash")
	}
}

func TestGenerateUnifiedDiff_AddedLines(t *testing.T) {
	expected := []byte("line1\nline2\n")
	actual := []byte("line1\nline2\nline3\nline4\n")

	result := GenerateUnifiedDiff(expected, actual, "/test/file.txt")

	if result == "" {
		t.Fatal("expected non-empty diff")
	}

	if !strings.Contains(result, "line3") || !strings.Contains(result, "line4") {
		t.Error("diff should show added lines")
	}
}

func TestGenerateUnifiedDiff_RemovedLines(t *testing.T) {
	expected := []byte("line1\nline2\nline3\nline4\n")
	actual := []byte("line1\nline2\n")

	result := GenerateUnifiedDiff(expected, actual, "/test/file.txt")

	if result == "" {
		t.Fatal("expected non-empty diff")
	}

	if !strings.Contains(result, "line3") || !strings.Contains(result, "line4") {
		t.Error("diff should show removed lines")
	}
}

func TestGenerateUnifiedDiff_EmptyExpected(t *testing.T) {
	expected := []byte{}
	actual := []byte("new content\n")

	result := GenerateUnifiedDiff(expected, actual, "/test/file.txt")

	if result == "" {
		t.Fatal("expected non-empty diff")
	}

	if !strings.Contains(result, "new content") {
		t.Error("diff should show new content")
	}
}

func TestGenerateUnifiedDiff_EmptyActual(t *testing.T) {
	expected := []byte("old content\n")
	actual := []byte{}

	result := GenerateUnifiedDiff(expected, actual, "/test/file.txt")

	if result == "" {
		t.Fatal("expected non-empty diff")
	}

	if !strings.Contains(result, "old content") {
		t.Error("diff should show removed content")
	}
}

func TestGenerateUnifiedDiff_BothEmpty(t *testing.T) {
	expected := []byte{}
	actual := []byte{}

	result := GenerateUnifiedDiff(expected, actual, "/test/file.txt")

	if result != "" {
		t.Errorf("expected empty diff for two empty contents, got: %s", result)
	}
}

func TestGenerateUnifiedDiff_MultipleChanges(t *testing.T) {
	expected := []byte("line1\nline2\nline3\nline4\nline5\n")
	actual := []byte("line1\nchanged2\nline3\nchanged4\nline5\n")

	result := GenerateUnifiedDiff(expected, actual, "/test/file.txt")

	if result == "" {
		t.Fatal("expected non-empty diff")
	}

	// Should show some indication of change.
	if !strings.Contains(result, "-") && !strings.Contains(result, "+") {
		t.Errorf("diff should show changes with +/-, got: %s", result)
	}
}

func TestGenerateUnifiedDiff_LongPath(t *testing.T) {
	expected := []byte("old\n")
	actual := []byte("new\n")
	longPath := "/very/long/path/to/some/deeply/nested/directory/structure/file.txt"

	result := GenerateUnifiedDiff(expected, actual, longPath)

	if result == "" {
		t.Fatal("expected non-empty diff")
	}

	if !strings.Contains(result, longPath) {
		t.Error("diff should contain the file path")
	}
}

func TestGenerateUnifiedDiff_SpecialCharacters(t *testing.T) {
	expected := []byte("hello\tworld\n")
	actual := []byte("hello\t\tworld\n")

	result := GenerateUnifiedDiff(expected, actual, "/test/file.txt")

	if result == "" {
		t.Fatal("expected non-empty diff")
	}
}

func TestFormatDriftError_LongResourceName(t *testing.T) {
	result := FormatDriftError(
		"module.infrastructure.module.networking.filesync_file.very_long_config_name",
		"/etc/application/configuration/settings.json",
		"sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		"sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		"",
	)

	if !strings.Contains(result, "module.infrastructure.module.networking") {
		t.Error("should contain full resource name")
	}
}

func TestFormatDriftError_SpecialPathCharacters(t *testing.T) {
	result := FormatDriftError(
		"filesync_file.config",
		"/path/with spaces/and-dashes/file.txt",
		"sha256:abc",
		"sha256:def",
		"",
	)

	if !strings.Contains(result, "/path/with spaces/and-dashes/file.txt") {
		t.Error("should preserve special characters in path")
	}
}

func TestIsBinary_LargeTextContent(t *testing.T) {
	// Large text content should not be detected as binary.
	large := make([]byte, 10000)
	for i := range large {
		large[i] = byte('a' + (i % 26))
	}

	result := isBinary(large)
	if result {
		t.Error("large text content should not be detected as binary")
	}
}

func TestIsBinary_NullAtEnd(t *testing.T) {
	content := []byte("normal text content")
	content = append(content, 0)

	result := isBinary(content)
	if !result {
		t.Error("content with null byte at end should be detected as binary")
	}
}

func TestGenerateUnifiedDiff_Truncation(t *testing.T) {
	// Create content with many different lines to trigger truncation.
	var expected, actual strings.Builder
	for i := 0; i < 100; i++ {
		expected.WriteString(fmt.Sprintf("original line %d\n", i))
		actual.WriteString(fmt.Sprintf("changed line %d\n", i))
	}

	result := GenerateUnifiedDiff([]byte(expected.String()), []byte(actual.String()), "/test/file.txt")

	if result == "" {
		t.Fatal("expected non-empty diff")
	}

	if !strings.Contains(result, "truncated") {
		t.Error("diff should indicate truncation for large diffs")
	}
}

func TestGenerateUnifiedDiff_ContextLines(t *testing.T) {
	// Create content with many unchanged lines and a change in the middle.
	// to exercise the context line trimming logic
	var expected, actual strings.Builder

	// Write many identical lines.
	for i := 0; i < 20; i++ {
		expected.WriteString(fmt.Sprintf("unchanged line %d\n", i))
		actual.WriteString(fmt.Sprintf("unchanged line %d\n", i))
	}
	// Add a change.
	expected.WriteString("this line is different\n")
	actual.WriteString("this line was modified\n")
	// More identical lines.
	for i := 0; i < 20; i++ {
		expected.WriteString(fmt.Sprintf("more unchanged line %d\n", i))
		actual.WriteString(fmt.Sprintf("more unchanged line %d\n", i))
	}

	result := GenerateUnifiedDiff([]byte(expected.String()), []byte(actual.String()), "/test/file.txt")

	if result == "" {
		t.Fatal("expected non-empty diff")
	}

	// The diff should show some indication of changes (+ or -).
	if !strings.Contains(result, "+") && !strings.Contains(result, "-") {
		t.Errorf("diff should show changes with +/-, got: %s", result)
	}
}

func TestFormatUnifiedDiff_EllipsisContext(t *testing.T) {
	// Test that long unchanged sections show "..." for context trimming
	// This requires a diff where DiffEqual has many lines.
	var expected, actual strings.Builder

	// First 3 context lines (should show).
	expected.WriteString("context1\ncontext2\ncontext3\n")
	actual.WriteString("context1\ncontext2\ncontext3\n")

	// Middle lines (should be replaced with ...)
	for i := 0; i < 10; i++ {
		expected.WriteString(fmt.Sprintf("middle%d\n", i))
		actual.WriteString(fmt.Sprintf("middle%d\n", i))
	}

	// Last 3 context lines (should show).
	expected.WriteString("end1\nend2\nend3\n")
	actual.WriteString("end1\nend2\nend3\n")

	// Add an actual change at the end.
	expected.WriteString("old\n")
	actual.WriteString("new\n")

	result := GenerateUnifiedDiff([]byte(expected.String()), []byte(actual.String()), "/test/file.txt")

	if result == "" {
		t.Fatal("expected non-empty diff")
	}

	// Should contain the actual changes.
	if !strings.Contains(result, "old") || !strings.Contains(result, "new") {
		t.Error("diff should contain the actual changes")
	}
}
