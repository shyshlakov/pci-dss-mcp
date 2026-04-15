package secretscanner

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ParseYAMLFile parses a YAML file into KeyValue tuples using yaml.v3 Node API
// with line numbers. Returns KeyValue tuples with dot-separated key paths.
// Empty string values are skipped.
func ParseYAMLFile(path string) ([]KeyValue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse YAML %s: %w", path, err)
	}

	// Root should be a DocumentNode.
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, nil
	}

	var kvs []KeyValue
	walkYAMLNode(doc.Content[0], "", path, &kvs)
	return kvs, nil
}

// walkYAMLNode recursively walks a yaml.Node tree, building dot-separated key paths.
func walkYAMLNode(node *yaml.Node, prefix, filePath string, kvs *[]KeyValue) {
	switch node.Kind {
	case yaml.MappingNode:
		// Content is key-value pairs: [key0, val0, key1, val1,...]
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]

			key := keyNode.Value
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}

			walkYAMLNode(valNode, fullKey, filePath, kvs)
		}

	case yaml.SequenceNode:
		for i, child := range node.Content {
			indexKey := fmt.Sprintf("%s[%d]", prefix, i)
			walkYAMLNode(child, indexKey, filePath, kvs)
		}

	case yaml.ScalarNode:
		value := node.Value
		// Skip empty string values.
		if value == "" {
			return
		}
		*kvs = append(*kvs, KeyValue{
			Key:      prefix,
			Value:    value,
			Line:     node.Line,
			FilePath: filePath,
		})
	}
}
