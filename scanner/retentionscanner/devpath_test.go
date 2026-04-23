package retentionscanner

import "testing"

func TestIsDevConfigPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"empty path", "", false},
		{"prod configs compose", "configs/docker-compose.yml", false},
		{"dev_compose prefix", "clean/dev_compose/docker-compose.yml", true},
		{"deploy local", "deploy/local/app.yaml", true},
		{"deploy compose", "deploy/compose/app.yaml", true},
		{"internal testutil", "internal/testutil/fixtures.yaml", true},
		{"internal testutils", "internal/testutils/fixtures.yaml", true},
		{"test fixtures", "test/fixtures/app.yaml", true},
		{"cmd dev", "cmd/dev/seed.yaml", true},
		{"deploy prod compose", "deploy/prod/docker-compose.yml", false},
		{"configs cache", "configs/cache.yaml", false},
		{"uppercase configs", "CONFIGS/DOCKER-COMPOSE.yml", false},
		{"uppercase dev segment", "CLEAN/DEV_COMPOSE/docker-compose.yml", true},
		{"filename suffix dev ignored", "configs/docker-compose.dev.yml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDevConfigPath(tt.path)
			if got != tt.want {
				t.Errorf("isDevConfigPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestDevPathTriageHint(t *testing.T) {
	t.Parallel()
	hint := devPathTriageHint()
	const wantPrefix = "downgrade:dev_path_skipped | "
	if len(hint) <= len(wantPrefix) || hint[:len(wantPrefix)] != wantPrefix {
		t.Errorf("devPathTriageHint() = %q, want prefix %q", hint, wantPrefix)
	}
}
