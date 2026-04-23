package scanner_test

import (
	"math"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestShannonEntropy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantMin float64
		wantMax float64
	}{
		{
			name:    "empty string returns 0",
			input:   "",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "repeated single char has low entropy",
			input:   "aaaa",
			wantMin: 0,
			wantMax: 0.01,
		},
		{
			name:    "password has moderate entropy below 4.5",
			input:   "password",
			wantMin: 2.0,
			wantMax: 4.5,
		},
		{
			name:    "high entropy token exceeds 4.5",
			input:   "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
			wantMin: 4.5,
			wantMax: 6.0,
		},
		{
			name:    "semver has low entropy",
			input:   "v1.0.0",
			wantMin: 0,
			wantMax: 4.5,
		},
		{
			name:    "two distinct chars",
			input:   "ab",
			wantMin: 0.99,
			wantMax: 1.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanner.ShannonEntropy(tt.input)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("ShannonEntropy(%q) = %f, want [%f, %f]", tt.input, got, tt.wantMin, tt.wantMax)
			}
			// Entropy should never be negative.
			if got < 0 {
				t.Errorf("ShannonEntropy(%q) = %f, entropy should never be negative", tt.input, got)
			}
			// Entropy should never be NaN.
			if math.IsNaN(got) {
				t.Errorf("ShannonEntropy(%q) returned NaN", tt.input)
			}
		})
	}
}
