package diff

import (
	"fmt"
	"strings"

	"github.com/sergi/go-diff/diffmatchpatch"
)

const (
	// MaxDiffSize is the maximum file size (in bytes) for which we show diffs.
	MaxDiffSize = 100 * 1024 // 100KB

	// MaxDiffLines is the maximum number of diff lines to show.
	MaxDiffLines = 50
)

// GenerateUnifiedDiff creates a unified diff between expected and actual content.
// Returns empty string if content is too large or binary.
func GenerateUnifiedDiff(expected, actual []byte, filename string) string {
	// Check size limits.
	if len(expected) > MaxDiffSize || len(actual) > MaxDiffSize {
		return ""
	}

	// Check for binary content.
	if isBinary(expected) || isBinary(actual) {
		return ""
	}

	expectedStr := string(expected)
	actualStr := string(actual)

	// If content is identical, no diff needed.
	if expectedStr == actualStr {
		return ""
	}

	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(expectedStr, actualStr, true)

	// Convert to unified diff format.
	return formatUnifiedDiff(diffs, filename, MaxDiffLines)
}

// formatUnifiedDiff converts diff-match-patch output to a more readable format.
func formatUnifiedDiff(diffs []diffmatchpatch.Diff, filename string, maxLines int) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("--- expected: %s\n", filename))
	sb.WriteString(fmt.Sprintf("+++ actual: %s (remote)\n", filename))

	lineCount := 0
	for _, diff := range diffs {
		if lineCount >= maxLines {
			sb.WriteString("\n... (diff truncated, too many changes)\n")
			break
		}

		lines := strings.Split(diff.Text, "\n")
		for i, line := range lines {
			if lineCount >= maxLines {
				sb.WriteString("\n... (diff truncated, too many changes)\n")
				break
			}

			// Skip empty trailing line from split.
			if i == len(lines)-1 && line == "" {
				continue
			}

			switch diff.Type {
			case diffmatchpatch.DiffDelete:
				sb.WriteString(fmt.Sprintf("- %s\n", line))
				lineCount++
			case diffmatchpatch.DiffInsert:
				sb.WriteString(fmt.Sprintf("+ %s\n", line))
				lineCount++
			case diffmatchpatch.DiffEqual:
				// Show some context lines around changes.
				if i < 3 || i >= len(lines)-3 {
					sb.WriteString(fmt.Sprintf("  %s\n", line))
					lineCount++
				} else if i == 3 {
					sb.WriteString("  ...\n")
					lineCount++
				}
			}
		}
	}

	return sb.String()
}

// isBinary checks if content appears to be binary (contains null bytes).
func isBinary(content []byte) bool {
	// Check first 8KB for null bytes.
	checkLen := len(content)
	if checkLen > 8192 {
		checkLen = 8192
	}

	for i := 0; i < checkLen; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}

// FormatDriftError creates a formatted drift error message with optional diff.
func FormatDriftError(resourceID, filePath, expectedHash, actualHash string, diffContent string) string {
	var sb strings.Builder

	sb.WriteString("The remote file was modified outside of Terraform.\n\n")
	sb.WriteString(fmt.Sprintf("  Resource: %s\n", resourceID))
	sb.WriteString(fmt.Sprintf("  File: %s\n\n", filePath))
	sb.WriteString(fmt.Sprintf("  Expected (from state): %s\n", expectedHash))
	sb.WriteString(fmt.Sprintf("  Found (on remote):     %s\n", actualHash))

	if diffContent != "" {
		sb.WriteString("\n  Content diff:\n")
		// Indent the diff.
		for _, line := range strings.Split(diffContent, "\n") {
			if line != "" {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
	}

	sb.WriteString("\n  To resolve:\n")
	sb.WriteString("    - terraform apply -replace   # Force overwrite with local content\n")
	sb.WriteString("    - Remove from state and re-import   # Accept remote changes\n")

	return sb.String()
}
