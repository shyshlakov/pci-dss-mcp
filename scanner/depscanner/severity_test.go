package depscanner

import (
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestResolveSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		vuln     *Vulnerability
		expected scanner.Severity
	}{
		{
			name: "database_specific CRITICAL",
			vuln: &Vulnerability{
				DatabaseSpecific: DatabaseSpecific{Severity: "CRITICAL"},
			},
			expected: scanner.SeverityCritical,
		},
		{
			name: "database_specific HIGH",
			vuln: &Vulnerability{
				DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
			},
			expected: scanner.SeverityHigh,
		},
		{
			name: "database_specific MODERATE maps to MEDIUM",
			vuln: &Vulnerability{
				DatabaseSpecific: DatabaseSpecific{Severity: "MODERATE"},
			},
			expected: scanner.SeverityMedium,
		},
		{
			name: "database_specific LOW",
			vuln: &Vulnerability{
				DatabaseSpecific: DatabaseSpecific{Severity: "LOW"},
			},
			expected: scanner.SeverityLow,
		},
		{
			name: "CVSS 3.1 score 9.8 returns CRITICAL",
			vuln: &Vulnerability{
				SeverityData: []SeverityEntry{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
			},
			expected: scanner.SeverityCritical,
		},
		{
			name: "CVSS 3.1 score 7.5 returns HIGH",
			vuln: &Vulnerability{
				SeverityData: []SeverityEntry{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
				},
			},
			expected: scanner.SeverityHigh,
		},
		{
			name: "CVSS 3.1 score 5.3 returns MEDIUM",
			vuln: &Vulnerability{
				SeverityData: []SeverityEntry{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
				},
			},
			expected: scanner.SeverityMedium,
		},
		{
			name: "CVSS 3.1 score 3.1 returns LOW",
			vuln: &Vulnerability{
				SeverityData: []SeverityEntry{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"},
				},
			},
			expected: scanner.SeverityLow,
		},
		{
			name:     "no severity data returns HIGH default",
			vuln:     &Vulnerability{},
			expected: scanner.SeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveSeverity(tt.vuln)
			if got != tt.expected {
				t.Errorf("resolveSeverity() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParseCVSSBaseScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		vector    string
		wantMin   float64
		wantMax   float64
		wantError bool
	}{
		{
			name:    "CVSS 3.1 critical",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantMin: 9.0,
			wantMax: 10.0,
		},
		{
			name:    "CVSS 3.0 high",
			vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			wantMin: 7.0,
			wantMax: 8.9,
		},
		{
			name:    "CVSS 4.0 vector",
			vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			wantMin: 9.0,
			wantMax: 10.0,
		},
		{
			name:    "CVSS 2.0 vector",
			vector:  "AV:N/AC:L/Au:N/C:C/I:C/A:C",
			wantMin: 9.0,
			wantMax: 10.0,
		},
		{
			name:      "invalid vector string",
			vector:    "not-a-cvss-vector",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, err := parseCVSSBaseScore(tt.vector)
			if tt.wantError {
				if err == nil {
					t.Errorf("parseCVSSBaseScore() expected error, got score=%f", score)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCVSSBaseScore() unexpected error: %v", err)
			}
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("parseCVSSBaseScore() = %f, want between %f and %f", score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestIsAffected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		moduleVersion string
		ranges        []Range
		expected      bool
	}{
		{
			name:          "version within introduced..fixed range",
			moduleVersion: "v0.20.0",
			ranges: []Range{
				{
					Type: "SEMVER",
					Events: []Event{
						{Introduced: "0"},
						{Fixed: "0.23.0"},
					},
				},
			},
			expected: true,
		},
		{
			name:          "version at or above fixed",
			moduleVersion: "v0.23.0",
			ranges: []Range{
				{
					Type: "SEMVER",
					Events: []Event{
						{Introduced: "0"},
						{Fixed: "0.23.0"},
					},
				},
			},
			expected: false,
		},
		{
			name:          "version above fixed",
			moduleVersion: "v0.24.0",
			ranges: []Range{
				{
					Type: "SEMVER",
					Events: []Event{
						{Introduced: "0"},
						{Fixed: "0.23.0"},
					},
				},
			},
			expected: false,
		},
		{
			name:          "zero introduced means all versions from beginning",
			moduleVersion: "v0.1.0",
			ranges: []Range{
				{
					Type: "SEMVER",
					Events: []Event{
						{Introduced: "0"},
						{Fixed: "1.0.0"},
					},
				},
			},
			expected: true,
		},
		{
			name:          "specific introduced version - below range",
			moduleVersion: "v1.0.0",
			ranges: []Range{
				{
					Type: "SEMVER",
					Events: []Event{
						{Introduced: "1.1.0"},
						{Fixed: "1.5.0"},
					},
				},
			},
			expected: false,
		},
		{
			name:          "specific introduced version - within range",
			moduleVersion: "v1.2.0",
			ranges: []Range{
				{
					Type: "SEMVER",
					Events: []Event{
						{Introduced: "1.1.0"},
						{Fixed: "1.5.0"},
					},
				},
			},
			expected: true,
		},
		{
			name:          "ECOSYSTEM range type works",
			moduleVersion: "v0.20.0",
			ranges: []Range{
				{
					Type: "ECOSYSTEM",
					Events: []Event{
						{Introduced: "0"},
						{Fixed: "0.23.0"},
					},
				},
			},
			expected: true,
		},
		{
			name:          "unsupported range type ignored",
			moduleVersion: "v0.20.0",
			ranges: []Range{
				{
					Type: "GIT",
					Events: []Event{
						{Introduced: "0"},
						{Fixed: "0.23.0"},
					},
				},
			},
			expected: false,
		},
		{
			name:          "no fixed version - last_affected only",
			moduleVersion: "v0.20.0",
			ranges: []Range{
				{
					Type: "SEMVER",
					Events: []Event{
						{Introduced: "0"},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAffected(tt.moduleVersion, tt.ranges)
			if got != tt.expected {
				t.Errorf("isAffected(%q) = %v, want %v", tt.moduleVersion, got, tt.expected)
			}
		})
	}
}

func TestDeduplicateVulns(t *testing.T) {
	t.Parallel()
	t.Run("groups GHSA and GO entries sharing CVE alias", func(t *testing.T) {
		vulns := []*Vulnerability{
			{
				ID:               "GHSA-xxxx-xxxx-xxxx",
				Aliases:          []string{"CVE-2024-1234"},
				DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
			},
			{
				ID:      "GO-2024-1234",
				Aliases: []string{"CVE-2024-1234"},
			},
		}

		result := deduplicateVulns(vulns)
		if len(result) != 1 {
			t.Fatalf("deduplicateVulns() returned %d entries, want 1", len(result))
		}
	})

	t.Run("prefers GHSA entry with severity data", func(t *testing.T) {
		vulns := []*Vulnerability{
			{
				ID:      "GO-2024-1234",
				Aliases: []string{"CVE-2024-1234"},
			},
			{
				ID:               "GHSA-xxxx-xxxx-xxxx",
				Aliases:          []string{"CVE-2024-1234"},
				DatabaseSpecific: DatabaseSpecific{Severity: "CRITICAL"},
			},
		}

		result := deduplicateVulns(vulns)
		if len(result) != 1 {
			t.Fatalf("deduplicateVulns() returned %d entries, want 1", len(result))
		}
		if result[0].DatabaseSpecific.Severity != "CRITICAL" {
			t.Errorf("expected GHSA entry with severity CRITICAL, got %q", result[0].DatabaseSpecific.Severity)
		}
	})

	t.Run("preserves all IDs in combined aliases", func(t *testing.T) {
		vulns := []*Vulnerability{
			{
				ID:               "GHSA-xxxx-xxxx-xxxx",
				Aliases:          []string{"CVE-2024-1234"},
				DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
			},
			{
				ID:      "GO-2024-1234",
				Aliases: []string{"CVE-2024-1234"},
			},
		}

		result := deduplicateVulns(vulns)
		if len(result) != 1 {
			t.Fatalf("deduplicateVulns() returned %d entries, want 1", len(result))
		}

		allIDs := make(map[string]bool)
		allIDs[result[0].ID] = true
		for _, alias := range result[0].Aliases {
			allIDs[alias] = true
		}

		for _, id := range []string{"GHSA-xxxx-xxxx-xxxx", "GO-2024-1234", "CVE-2024-1234"} {
			if !allIDs[id] {
				t.Errorf("expected %q in combined IDs/aliases, not found", id)
			}
		}
	})

	t.Run("unrelated vulns not deduplicated", func(t *testing.T) {
		vulns := []*Vulnerability{
			{
				ID:      "GHSA-aaaa-aaaa-aaaa",
				Aliases: []string{"CVE-2024-1111"},
			},
			{
				ID:      "GHSA-bbbb-bbbb-bbbb",
				Aliases: []string{"CVE-2024-2222"},
			},
		}

		result := deduplicateVulns(vulns)
		if len(result) != 2 {
			t.Fatalf("deduplicateVulns() returned %d entries, want 2", len(result))
		}
	})
}
