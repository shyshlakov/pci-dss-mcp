package secretscanner

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// ParseEnvFile parses a.env file into KeyValue tuples.
// Handles comments (#), empty lines, export prefix stripping,
// KEY=VALUE split on first =, and quote stripping.
// Empty values are skipped.
func ParseEnvFile(path string) ([]KeyValue, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Warn("close env file", "path", path, "err", cerr)
		}
	}()

	var kvs []KeyValue
	lineNum := 0

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNum++
		line := sc.Text()

		// Skip empty lines and comments.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Strip "export " prefix.
		if strings.HasPrefix(trimmed, "export ") {
			trimmed = strings.TrimPrefix(trimmed, "export ")
			trimmed = strings.TrimSpace(trimmed)
		}

		// Split on first '=' to get key and value.
		eqIdx := strings.Index(trimmed, "=")
		if eqIdx < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eqIdx])
		value := strings.TrimSpace(trimmed[eqIdx+1:])

		// Strip surrounding quotes from value.
		value = stripQuotes(value)

		// Skip empty values.
		if value == "" {
			continue
		}

		kvs = append(kvs, KeyValue{
			Key:      key,
			Value:    value,
			Line:     lineNum,
			FilePath: path,
		})
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	return kvs, nil
}

// stripQuotes removes surrounding double or single quotes from a string.
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
