package secretscanner

import (
	"encoding/json"
	"fmt"
	"os"
)

// maxJSONDepth is the maximum recursion depth for JSON map walking.
// Prevents stack overflow on adversarial files (T-04-01).
const maxJSONDepth = 20

// ParseJSONFile parses a JSON file into KeyValue tuples with dot-separated key
// paths. Line is always 0 (JSON limitation). Empty string values are skipped.
func ParseJSONFile(path string) ([]KeyValue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Strip JSONC comments and trailing commas before parsing (R11-01).
	data = StripJSONComments(data)

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse JSON %s: %w", path, err)
	}

	var kvs []KeyValue
	walkJSONMap(root, "", path, 0, &kvs)
	return kvs, nil
}

// walkJSONMap recursively walks a JSON map, building dot-separated key paths.
func walkJSONMap(m map[string]any, prefix, filePath string, depth int, kvs *[]KeyValue) {
	if depth >= maxJSONDepth {
		return
	}

	for key, val := range m {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := val.(type) {
		case string:
			if v == "" {
				continue
			}
			*kvs = append(*kvs, KeyValue{
				Key:      fullKey,
				Value:    v,
				Line:     0,
				FilePath: filePath,
			})
		case map[string]any:
			walkJSONMap(v, fullKey, filePath, depth+1, kvs)
		case []any:
			walkJSONSlice(v, fullKey, filePath, depth+1, kvs)
		// JSON numbers, booleans: convert to string
		case float64:
			*kvs = append(*kvs, KeyValue{
				Key:      fullKey,
				Value:    fmt.Sprintf("%v", v),
				Line:     0,
				FilePath: filePath,
			})
		case bool:
			*kvs = append(*kvs, KeyValue{
				Key:      fullKey,
				Value:    fmt.Sprintf("%v", v),
				Line:     0,
				FilePath: filePath,
			})
			// nil values are skipped
		}
	}
}

// walkJSONSlice handles JSON arrays.
func walkJSONSlice(arr []any, prefix, filePath string, depth int, kvs *[]KeyValue) {
	if depth >= maxJSONDepth {
		return
	}

	for i, val := range arr {
		indexKey := fmt.Sprintf("%s[%d]", prefix, i)
		switch v := val.(type) {
		case string:
			if v == "" {
				continue
			}
			*kvs = append(*kvs, KeyValue{
				Key:      indexKey,
				Value:    v,
				Line:     0,
				FilePath: filePath,
			})
		case map[string]any:
			walkJSONMap(v, indexKey, filePath, depth+1, kvs)
		case []any:
			walkJSONSlice(v, indexKey, filePath, depth+1, kvs)
		case float64:
			*kvs = append(*kvs, KeyValue{
				Key:      indexKey,
				Value:    fmt.Sprintf("%v", v),
				Line:     0,
				FilePath: filePath,
			})
		case bool:
			*kvs = append(*kvs, KeyValue{
				Key:      indexKey,
				Value:    fmt.Sprintf("%v", v),
				Line:     0,
				FilePath: filePath,
			})
		}
	}
}
