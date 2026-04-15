package scanner

import (
	"os"
	"strings"
)

// ReadCodeSnippet reads +-2 lines around the given line number from filePath.
// Returns nil if file cannot be read or line is out of range.
// Line numbers are 1-based.
func ReadCodeSnippet(filePath string, line int) *CodeSnippet {
	if line < 1 {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	if line > len(lines) {
		return nil
	}

	idx := line - 1 // 0-based index

	// Collect before lines (up to 2).
	var beforeLines []string
	for i := max(0, idx-2); i < idx; i++ {
		beforeLines = append(beforeLines, lines[i])
	}

	// Collect after lines (up to 2).
	var afterLines []string
	for i := idx + 1; i < min(len(lines), idx+3); i++ {
		afterLines = append(afterLines, lines[i])
	}

	return &CodeSnippet{
		Before: strings.Join(beforeLines, "\n"),
		Line:   lines[idx],
		After:  strings.Join(afterLines, "\n"),
	}
}
