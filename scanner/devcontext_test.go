package scanner

import "testing"

func TestIsProdPath(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{"config/prod.yaml", "config/prod.yaml", true},
		{"config/production.yaml", "config/production.yaml", true},
		{"config/production/db.yaml", "config/production/db.yaml", true},
		{".env.production", ".env.production", true},
		{".env.prod", ".env.prod", true},
		{"k8s/deployment.yaml", "k8s/deployment.yaml", true},
		{"kubernetes/secrets.yaml", "kubernetes/secrets.yaml", true},
		{"deploy/prod/config.yaml", "deploy/prod/config.yaml", true},
		// Negative cases.
		{"src/main.go", "src/main.go", false},
		{"docker-compose.yml", "docker-compose.yml", false},
		{"config/dev.yaml", "config/dev.yaml", false},
		{".env.local", ".env.local", false},
		{".env", ".env", false},
		{"test/config.yaml", "test/config.yaml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProdPath(tt.filePath)
			if got != tt.want {
				t.Errorf("isProdPath(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestIsDevPath(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{"docker-compose.dev.yml", "docker-compose.dev.yml", true},
		{"docker-compose.local.yml", "docker-compose.local.yml", true},
		{"docker-compose.override.yml", "docker-compose.override.yml", true},
		{".env.local", ".env.local", true},
		{".env.dev", ".env.dev", true},
		{".env.development", ".env.development", true},
		{".env.example", ".env.example", true},
		{".env.sample", ".env.sample", true},
		{".env.template", ".env.template", true},
		{"deploy/dev/config.yaml", "deploy/dev/config.yaml", true},
		// D-path-dep: "testdata" is no longer a dev segment — it is a Go
		// language convention for static fixtures, not a dev-env marker.
		{"testdata/fixtures.yaml NOT dev (D-path-dep)", "testdata/fixtures.yaml", false},
		{"fixtures/test.env", "fixtures/test.env", true},
		{"e2e/config.yaml", "e2e/config.yaml", true},
		{"test/config.yaml", "test/config.yaml", true},
		{"local/settings.yaml", "local/settings.yaml", true},
		// docker-compose.yml (no suffix) is NOT dev.
		{"docker-compose.yml NOT dev ", "docker-compose.yml", false},
		// Negative cases.
		{"src/main.go", "src/main.go", false},
		{"config/prod.yaml", "config/prod.yaml", false},
		{".env", ".env", false},
		{".env.prod", ".env.prod", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDevPath(tt.filePath, "")
			if got != tt.want {
				t.Errorf("isDevPath(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestIsPlaceholderValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"changeme", "changeme", true},
		{"Password case-insensitive", "Password", true},
		{"localhost", "localhost", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"test123", "test123", true},
		{"dummy", "dummy", true},
		{"placeholder", "placeholder", true},
		{"secret", "secret", true},
		{"example", "example", true},
		{"CHANGEME uppercase", "CHANGEME", true},
		// Negative cases.
		{"sk_live_abc123", "sk_live_abc123", false},
		{"realSecret123!", "realSecret123!", false},
		{"complex-password-here", "complex-password-here", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPlaceholderValue(tt.value)
			if got != tt.want {
				t.Errorf("isPlaceholderValue(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestClassifyDevContext(t *testing.T) {
	tests := []struct {
		name              string
		filePath          string
		value             string
		originalSev       Severity
		wantIsProdPath    bool
		wantIsDevPath     bool
		wantIsPlaceholder bool
		wantDedicatedDev  bool
		wantAdjustedSev   Severity
		wantLabel         string
	}{
		// Prod paths always stay CRITICAL regardless of placeholder.
		{
			name:            "prod path with changeme stays CRITICAL ",
			filePath:        "config/prod.yaml",
			value:           "changeme",
			originalSev:     SeverityHigh,
			wantIsProdPath:  true,
			wantAdjustedSev: SeverityCritical,
			wantLabel:       "",
		},
		{
			name:            "production.yaml with weak stays CRITICAL",
			filePath:        "config/production.yaml",
			value:           "weak",
			originalSev:     SeverityHigh,
			wantIsProdPath:  true,
			wantAdjustedSev: SeverityCritical,
			wantLabel:       "",
		},
		{
			name:            "k8s/secrets.yaml stays CRITICAL",
			filePath:        "k8s/secrets.yaml",
			value:           "test123",
			originalSev:     SeverityCritical,
			wantIsProdPath:  true,
			wantAdjustedSev: SeverityCritical,
			wantLabel:       "",
		},
		{
			name:            ".env.prod with changeme stays CRITICAL",
			filePath:        ".env.prod",
			value:           "changeme",
			originalSev:     SeverityHigh,
			wantIsProdPath:  true,
			wantAdjustedSev: SeverityCritical,
			wantLabel:       "",
		},
		// Dev path only (no placeholder).
		// Also matches dedicatedDevSegments because "dev" segment is present.
		{
			name:             "dev path with real secret -> MEDIUM ",
			filePath:         "deploy/dev/config.yaml",
			value:            "realSecret123!",
			originalSev:      SeverityHigh,
			wantIsDevPath:    true,
			wantDedicatedDev: true,
			wantAdjustedSev:  SeverityMedium,
			wantLabel:        "dev-context",
		},
		// Dev path + placeholder -> INFO.
		{
			name:              "docker-compose.dev.yml + placeholder -> INFO ",
			filePath:          "docker-compose.dev.yml",
			value:             "password",
			originalSev:       SeverityHigh,
			wantIsDevPath:     true,
			wantIsPlaceholder: true,
			wantAdjustedSev:   SeverityInfo,
			wantLabel:         "dev-context",
		},
		// docker-compose.yml (no suffix) is NOT dev.
		{
			name:              "docker-compose.yml + placeholder -> MEDIUM ",
			filePath:          "docker-compose.yml",
			value:             "password",
			originalSev:       SeverityHigh,
			wantIsPlaceholder: true,
			wantAdjustedSev:   SeverityMedium,
			wantLabel:         "dev-context",
		},
		// Dev path + placeholder.
		{
			name:              ".env.local with secret -> INFO",
			filePath:          ".env.local",
			value:             "secret",
			originalSev:       SeverityHigh,
			wantIsDevPath:     true,
			wantIsPlaceholder: true,
			wantAdjustedSev:   SeverityInfo,
			wantLabel:         "dev-context",
		},
		// Dev path only (no placeholder).
		{
			name:            ".env.example with example_key -> MEDIUM",
			filePath:        ".env.example",
			value:           "example_key",
			originalSev:     SeverityCritical,
			wantIsDevPath:   true,
			wantAdjustedSev: SeverityMedium,
			wantLabel:       "dev-context",
		},
		// Placeholder only (no dev path).
		{
			name:              "src/config.go with changeme -> MEDIUM ",
			filePath:          "src/config.go",
			value:             "changeme",
			originalSev:       SeverityHigh,
			wantIsPlaceholder: true,
			wantAdjustedSev:   SeverityMedium,
			wantLabel:         "dev-context",
		},
		// Neither dev nor placeholder -- no change.
		{
			name:            "src/config.go with real secret -> unchanged",
			filePath:        "src/config.go",
			value:           "realSecret123!",
			originalSev:     SeverityHigh,
			wantAdjustedSev: SeverityHigh,
			wantLabel:       "",
		},
		// D-path-dep: testdata/ is no longer a dev segment; localhost is still
		// a placeholder, so severity downgrades one tier (HIGH -> MEDIUM).
		{
			name:              "testdata/fixtures.yaml + localhost -> MEDIUM (placeholder only)",
			filePath:          "testdata/fixtures.yaml",
			value:             "localhost",
			originalSev:       SeverityHigh,
			wantIsDevPath:     false,
			wantIsPlaceholder: true,
			wantAdjustedSev:   SeverityMedium,
			wantLabel:         "dev-context",
		},
		{
			name:              "docker-compose.override.yml + dummy -> INFO",
			filePath:          "docker-compose.override.yml",
			value:             "dummy",
			originalSev:       SeverityHigh,
			wantIsDevPath:     true,
			wantIsPlaceholder: true,
			wantAdjustedSev:   SeverityInfo,
			wantLabel:         "dev-context",
		},
		{
			name:              ".env.template + placeholder -> INFO",
			filePath:          ".env.template",
			value:             "placeholder",
			originalSev:       SeverityHigh,
			wantIsDevPath:     true,
			wantIsPlaceholder: true,
			wantAdjustedSev:   SeverityInfo,
			wantLabel:         "dev-context",
		},
		{
			name:              "fixtures/test.env + 127.0.0.1 -> INFO",
			filePath:          "fixtures/test.env",
			value:             "127.0.0.1",
			originalSev:       SeverityCritical,
			wantIsDevPath:     true,
			wantIsPlaceholder: true,
			wantAdjustedSev:   SeverityInfo,
			wantLabel:         "dev-context",
		},
		// dedicated-dev directories set DedicatedDev=true.
		// Classifier itself still only downgrades one tier (HIGH->MEDIUM);
		// callers consult dc.DedicatedDev to apply the extra downgrade to Info.
		{
			name:             "dedicated_dev_local_config",
			filePath:         "dev/local/configs/service.env",
			value:            "real-looking-pass",
			originalSev:      SeverityHigh,
			wantIsDevPath:    true,
			wantDedicatedDev: true,
			wantAdjustedSev:  SeverityMedium,
			wantLabel:        "dev-context",
		},
		{
			name:             "dedicated_dev_docker_compose",
			filePath:         "dev/local/docker-compose.yml",
			value:            "abc123def",
			originalSev:      SeverityHigh,
			wantIsDevPath:    true,
			wantDedicatedDev: true,
			wantAdjustedSev:  SeverityMedium,
			wantLabel:        "dev-context",
		},
		// "development" is dedicated-dev only; NOT in devPathSegments, so
		// IsDevPath=false and classifier does not apply the one-tier downgrade.
		// Caller-side tests cover the Info downgrade via dc.DedicatedDev.
		{
			name:             "dedicated_dev_development_dir",
			filePath:         "development/config.yaml",
			value:            "realSecret123!",
			originalSev:      SeverityHigh,
			wantDedicatedDev: true,
			wantAdjustedSev:  SeverityHigh,
			wantLabel:        "",
		},
		{
			name:             "dedicated_dev_sandbox_dir",
			filePath:         "sandbox/.env",
			value:            "realSecret123!",
			originalSev:      SeverityHigh,
			wantDedicatedDev: true,
			wantAdjustedSev:  SeverityHigh, // sandbox is NOT in devPathSegments; no one-tier downgrade
			wantLabel:        "",
		},
		// D-path-dep: testdata/ is no longer a dev segment, so this path is
		// treated as ordinary source and severity stays at the original tier.
		{
			name:            "regular_dev_testdata_not_dedicated",
			filePath:        "internal/testdata/fixture.env",
			value:           "realSecret123!",
			originalSev:     SeverityHigh,
			wantIsDevPath:   false,
			wantAdjustedSev: SeverityHigh,
			wantLabel:       "",
		},
		// _test.go suffix is not a path segment match; the classifier only
		// looks at directory segments, so IsDevPath=false here. The important
		// assertion is DedicatedDev=false -- no Info downgrade from callers.
		{
			name:            "regular_dev_test_file_not_dedicated",
			filePath:        "internal/foo_test.go",
			value:           "realSecret123!",
			originalSev:     SeverityHigh,
			wantAdjustedSev: SeverityHigh,
			wantLabel:       "",
		},
		{
			name:            "prod_path_override_wins",
			filePath:        "config/prod/service.env",
			value:           "realSecret123!",
			originalSev:     SeverityHigh,
			wantIsProdPath:  true,
			wantAdjustedSev: SeverityCritical,
			wantLabel:       "",
		},
		// "test" in dedicatedDevSegments -> DedicatedDev=true.
		// "test" is also in devPathSegments, so IsDevPath=true and classifier
		// applies one-tier downgrade (HIGH->MEDIUM). Callers apply extra
		// downgrade to Info via DedicatedDev flag.
		{
			name:             "dedicated_dev_test_dir ",
			filePath:         "internal/test/constants/constants.go",
			value:            "secretvalue",
			originalSev:      SeverityMedium,
			wantIsDevPath:    true,
			wantDedicatedDev: true,
			wantAdjustedSev:  SeverityMedium, // classifier: same tier (Medium->Medium no change)
			wantLabel:        "dev-context",
		},
		{
			name:             "dedicated_dev_test_fixtures ",
			filePath:         "test/fixtures/data.go",
			value:            "realSecret123!",
			originalSev:      SeverityHigh,
			wantIsDevPath:    true,
			wantDedicatedDev: true,
			wantAdjustedSev:  SeverityMedium,
			wantLabel:        "dev-context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := ClassifyDevContext(tt.filePath, tt.value, tt.originalSev)

			if dc.IsProdPath != tt.wantIsProdPath {
				t.Errorf("IsProdPath = %v, want %v", dc.IsProdPath, tt.wantIsProdPath)
			}
			if dc.IsDevPath != tt.wantIsDevPath {
				t.Errorf("IsDevPath = %v, want %v", dc.IsDevPath, tt.wantIsDevPath)
			}
			if dc.IsPlaceholder != tt.wantIsPlaceholder {
				t.Errorf("IsPlaceholder = %v, want %v", dc.IsPlaceholder, tt.wantIsPlaceholder)
			}
			if dc.DedicatedDev != tt.wantDedicatedDev {
				t.Errorf("DedicatedDev = %v, want %v", dc.DedicatedDev, tt.wantDedicatedDev)
			}
			if dc.AdjustedSev != tt.wantAdjustedSev {
				t.Errorf("AdjustedSev = %q, want %q", dc.AdjustedSev, tt.wantAdjustedSev)
			}
			if dc.Label != tt.wantLabel {
				t.Errorf("Label = %q, want %q", dc.Label, tt.wantLabel)
			}
			if dc.OriginalSev != tt.originalSev {
				t.Errorf("OriginalSev = %q, want %q", dc.OriginalSev, tt.originalSev)
			}
		})
	}
}

// TestDedicatedDevDirectoryList verifies,: paths under dedicated-dev
// directories (dev/, local/, development/, sandbox/, test/) set DedicatedDev=true.
func TestDedicatedDevDirectoryList(t *testing.T) {
	cases := []string{
		"dev/x.env",
		"local/x.env",
		"development/x.env",
		"sandbox/x.env",
		"dev/local/configs/x.env",
		"internal/test/constants/constants.go",
		"test/fixtures/data.go",
	}
	for _, p := range cases {
		dc := ClassifyDevContext(p, "v", SeverityHigh)
		if !dc.DedicatedDev {
			t.Errorf("path %s: DedicatedDev = false, want true", p)
		}
	}
}

// TestDedicatedDevNegatives verifies paths that must NOT set DedicatedDev.
func TestDedicatedDevNegatives(t *testing.T) {
	cases := []string{
		"internal/testdata/fixture.env",
		"internal/foo_test.go", // _test.go suffix, not a "test" directory segment
		"fixtures/sample.env",
		"e2e/config.yaml",
		"src/main.go",
	}
	for _, p := range cases {
		dc := ClassifyDevContext(p, "v", SeverityHigh)
		if dc.DedicatedDev {
			t.Errorf("path %s: DedicatedDev = true, want false", p)
		}
	}
}
