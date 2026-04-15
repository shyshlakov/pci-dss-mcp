package secretscanner

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// maxTOMLDepth is the maximum recursion depth for TOML map walking.
// Prevents stack overflow on adversarial files (T-04-01).
const maxTOMLDepth = 20

// ParseTOMLFile parses a TOML file into KeyValue tuples with dot-separated key
// paths. Line is always 0 (TOML map decode does not expose line numbers).
// Empty string values are skipped.
func ParseTOMLFile(path string) ([]KeyValue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var root map[string]any
	if err := toml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse TOML %s: %w", path, err)
	}

	var kvs []KeyValue
	walkTOMLMap(root, "", path, 0, &kvs)
	return kvs, nil
}

// walkTOMLMap recursively walks a TOML map, building dot-separated key paths.
// TOML values can be time.Time, int64, float64, bool -- all non-map, non-slice
// values are converted to string via fmt.Sprintf.
func walkTOMLMap(m map[string]any, prefix, filePath string, depth int, kvs *[]KeyValue) {
	if depth >= maxTOMLDepth {
		return
	}

	for key, val := range m {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := val.(type) {
		case map[string]any:
			walkTOMLMap(v, fullKey, filePath, depth+1, kvs)
		case []any:
			walkTOMLSlice(v, fullKey, filePath, depth+1, kvs)
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
		default:
			// int64, float64, bool, time.Time, etc.
			str := fmt.Sprintf("%v", v)
			if str == "" {
				continue
			}
			*kvs = append(*kvs, KeyValue{
				Key:      fullKey,
				Value:    str,
				Line:     0,
				FilePath: filePath,
			})
		}
	}
}

// walkTOMLSlice handles TOML arrays.
func walkTOMLSlice(arr []any, prefix, filePath string, depth int, kvs *[]KeyValue) {
	if depth >= maxTOMLDepth {
		return
	}

	for i, val := range arr {
		indexKey := fmt.Sprintf("%s[%d]", prefix, i)
		switch v := val.(type) {
		case map[string]any:
			walkTOMLMap(v, indexKey, filePath, depth+1, kvs)
		case []any:
			walkTOMLSlice(v, indexKey, filePath, depth+1, kvs)
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
		default:
			str := fmt.Sprintf("%v", v)
			if str == "" {
				continue
			}
			*kvs = append(*kvs, KeyValue{
				Key:      indexKey,
				Value:    str,
				Line:     0,
				FilePath: filePath,
			})
		}
	}
}
