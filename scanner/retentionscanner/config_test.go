package retentionscanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectConfigMissingTTL_SkipsNonConfigFiles(t *testing.T) {
	tests := []struct {
		name         string
		filename     string
		content      string
		wantFindings int
	}{
		// --- Filename heuristic: skip non-application configs ---
		{
			name:         "swagger.json skipped by filename",
			filename:     "swagger.json",
			content:      `{"swagger":"2.0","info":{"title":"API"},"paths":{"/payment":{"post":{"parameters":[{"name":"card_data","in":"body"}]}}}}`,
			wantFindings: 0,
		},
		{
			name:         "swagger.yaml skipped by filename",
			filename:     "swagger.yaml",
			content:      "swagger: '2.0'\ninfo:\n  title: API\npaths:\n  /payment:\n    post:\n      parameters:\n        - name: card_data\n          in: body\n",
			wantFindings: 0,
		},
		{
			name:         "openapi.json skipped by filename",
			filename:     "openapi.json",
			content:      `{"openapi":"3.0.0","info":{"title":"API"},"components":{"schemas":{"Payment":{"properties":{"card_data":{"type":"string"}}}}}}`,
			wantFindings: 0,
		},
		{
			name:         "openapi.yaml skipped by filename",
			filename:     "openapi.yaml",
			content:      "openapi: '3.0.0'\ninfo:\n  title: API\ncomponents:\n  schemas:\n    Payment:\n      properties:\n        card_data:\n          type: string\n",
			wantFindings: 0,
		},
		{
			name:         "package.json skipped by filename",
			filename:     "package.json",
			content:      `{"name":"payment-service","version":"1.0.0","dependencies":{"card-validator":"^10.0.0"}}`,
			wantFindings: 0,
		},
		{
			name:         "tsconfig.json skipped by filename",
			filename:     "tsconfig.json",
			content:      `{"compilerOptions":{"target":"es2020"},"include":["src/payment/**/*"]}`,
			wantFindings: 0,
		},
		// --- Path segment heuristic ---
		{
			name:         "file in /docs/ directory skipped",
			filename:     "config.json",
			content:      `{"payment":{"card_data":{"host":"localhost"}}}`,
			wantFindings: 0,
		},
		{
			name:         "file in /flagd/ directory skipped",
			filename:     "config.json",
			content:      `{"payment":{"card_data":{"host":"localhost"}}}`,
			wantFindings: 0,
		},
		// --- Basename indicator words ---
		{
			name:         "filename containing example skipped",
			filename:     "config.example.json",
			content:      `{"payment":{"card_data":{"host":"localhost"}}}`,
			wantFindings: 0,
		},
		{
			name:         "filename containing sample skipped",
			filename:     "sample-config.yaml",
			content:      "payment:\n  card_data:\n    host: localhost\n",
			wantFindings: 0,
		},
		{
			name:         "filename containing fixture skipped",
			filename:     "fixture_config.json",
			content:      `{"payment":{"card_data":{"host":"localhost"}}}`,
			wantFindings: 0,
		},
		{
			name:         "filename containing mock skipped",
			filename:     "mock-settings.yaml",
			content:      "payment:\n  card_data:\n    host: localhost\n",
			wantFindings: 0,
		},
		// --- Content fingerprinting: schema/doc files ---
		{
			name:         "JSON with top-level $schema key skipped",
			filename:     "schema.json",
			content:      `{"$schema":"http://json-schema.org/draft-07/schema#","properties":{"payment":{"card_data":{"type":"object"}}}}`,
			wantFindings: 0,
		},
		{
			name:         "JSON with top-level definitions key skipped",
			filename:     "types.json",
			content:      `{"definitions":{"PaymentCard":{"properties":{"card_data":{"type":"string"}}}}}`,
			wantFindings: 0,
		},
		{
			name:         "JSON with top-level components key skipped",
			filename:     "api-spec.json",
			content:      `{"components":{"schemas":{"Card":{"properties":{"card_data":{"type":"string"}}}}}}`,
			wantFindings: 0,
		},
		{
			name:         "JSON with swagger content fingerprint skipped",
			filename:     "api.json",
			content:      `{"swagger":"2.0","info":{"title":"Payment API"},"paths":{"/card":{"post":{"parameters":[{"name":"card_data"}]}}}}`,
			wantFindings: 0,
		},
		{
			name:         "JSON with openapi content fingerprint skipped",
			filename:     "spec.json",
			content:      `{"openapi":"3.0.0","info":{"title":"API"},"paths":{"/payment":{"post":{"parameters":[{"name":"card_data"}]}}}}`,
			wantFindings: 0,
		},
		// --- Feature flag configs ---
		{
			name:         "feature flag config with variants+enabled skipped",
			filename:     "flags.json",
			content:      `{"payment_feature":{"card_data":{"variants":{"on":"true","off":"false"},"enabled":true}}}`,
			wantFindings: 0,
		},
		// --- Regression: legitimate configs MUST still produce findings ---
		{
			name:         "legitimate config with cvv_cache and no TTL produces finding",
			filename:     "config.json",
			content:      `{"cvv_cache":{"host":"redis:6379","db":0}}`,
			wantFindings: 1,
		},
		{
			name:         "legitimate YAML with payment.card_data and no TTL produces finding",
			filename:     "config.yaml",
			content:      "payment:\n  card_data:\n    host: redis\n    db: 0\n",
			wantFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Handle path segment tests
			var path string
			switch tt.name {
			case "file in /docs/ directory skipped":
				docsDir := filepath.Join(tmpDir, "docs")
				if err := os.MkdirAll(docsDir, 0755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				path = filepath.Join(docsDir, tt.filename)
			case "file in /flagd/ directory skipped":
				flagdDir := filepath.Join(tmpDir, "flagd")
				if err := os.MkdirAll(flagdDir, 0755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				path = filepath.Join(flagdDir, tt.filename)
			default:
				path = filepath.Join(tmpDir, tt.filename)
			}

			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			findings, _, err := detectConfigMissingTTL(path)
			if err != nil {
				t.Fatalf("detectConfigMissingTTL: %v", err)
			}

			if len(findings) != tt.wantFindings {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantFindings)
				for i, f := range findings {
					t.Logf("  finding[%d]: %s %s %s", i, f.RuleID, f.Severity, f.Description)
				}
			}
		})
	}
}
