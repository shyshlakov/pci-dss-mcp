package panscanner

import (
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
)

// TestStructTagClassification is a table-driven test covering all classification
// cases for the struct tag heuristic. The heuristic inspects
// HasJSONTag and HasDBTag on a taint.Source to decide whether the enclosing
// struct is a transit API model, a storage/DB model, or inconclusive.
func TestStructTagClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		src  taint.Source
		want tagClass
	}{
		{
			name: "json tags only -> transit",
			src:  taint.Source{Package: "example.com/api", TypeName: "CardResponse", Field: "PAN", HasJSONTag: true, HasDBTag: false},
			want: tagClassTransit,
		},
		{
			name: "gorm tag -> storage",
			src:  taint.Source{Package: "example.com/model", TypeName: "Card", Field: "Number", HasJSONTag: false, HasDBTag: true},
			want: tagClassStorage,
		},
		{
			name: "db tag -> storage",
			src:  taint.Source{Package: "example.com/model", TypeName: "Card", Field: "Number", HasJSONTag: false, HasDBTag: true},
			want: tagClassStorage,
		},
		{
			name: "bun tag -> storage",
			src:  taint.Source{Package: "example.com/model", TypeName: "Card", Field: "Number", HasJSONTag: false, HasDBTag: true},
			want: tagClassStorage,
		},
		{
			name: "no tags at all -> inconclusive",
			src:  taint.Source{Package: "example.com/domain", TypeName: "ProvisionTokenCard", Field: "CVV", HasJSONTag: false, HasDBTag: false},
			want: tagClassInconclusive,
		},
		{
			name: "both json and gorm tags -> storage wins",
			src:  taint.Source{Package: "example.com/model", TypeName: "CardDB", Field: "Number", HasJSONTag: true, HasDBTag: true},
			want: tagClassStorage,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := structTagClassification(tc.src)
			if got != tc.want {
				t.Errorf("structTagClassification(%+v) = %d, want %d", tc.src, got, tc.want)
			}
		})
	}
}

// TestNegativeEvidenceTransit covers Option B: the "negative
// evidence" heuristic for Sensitive Authentication Data (SAD) fields in
// tagless domain models. When the struct tag heuristic returns inconclusive
// AND the taint engine's FlowsTo returned false AND the field name matches a
// well-known SAD keyword (CVV/CVC/CVC2/SecurityCode) AND the struct has no DB
// tags, negativeEvidenceTransit returns true — high-confidence transit signal
// that unblocks the PAN-KEYWORD/PAN-TYPE downgrade path.
//
// PAN field names (Number, PrimaryAccountNumber, AccountNumber) are
// deliberately EXCLUDED: PAN CAN be legitimately stored (with encryption per
// PCI DSS 3.5.1), so absence of a DB sink is weaker evidence for PAN than for
// SAD, which MUST be deleted after authorization per PCI DSS 3.3.1.
func TestNegativeEvidenceTransit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		src  taint.Source
		want bool
	}{
		{
			name: "CVV no DB tag -> true (SAD, never stored per 3.3.1)",
			src:  taint.Source{Package: "example.com/domain", TypeName: "ProvisionTokenCard", Field: "CVV", HasJSONTag: false, HasDBTag: false},
			want: true,
		},
		{
			name: "CVC no DB tag -> true (SAD alias)",
			src:  taint.Source{Package: "example.com/domain", TypeName: "Card", Field: "CVC", HasJSONTag: false, HasDBTag: false},
			want: true,
		},
		{
			name: "CVC2 no DB tag -> true (SAD alias)",
			src:  taint.Source{Package: "example.com/domain", TypeName: "Card", Field: "CVC2", HasJSONTag: false, HasDBTag: false},
			want: true,
		},
		{
			name: "CVV2 no DB tag -> true (SAD alias)",
			src:  taint.Source{Package: "example.com/domain", TypeName: "Card", Field: "CVV2", HasJSONTag: false, HasDBTag: false},
			want: true,
		},
		{
			name: "SecurityCode no DB tag -> true (SAD alias)",
			src:  taint.Source{Package: "example.com/domain", TypeName: "Card", Field: "SecurityCode", HasJSONTag: false, HasDBTag: false},
			want: true,
		},
		{
			name: "Number no DB tag -> false (PAN, can be legitimately stored)",
			src:  taint.Source{Package: "example.com/domain", TypeName: "Card", Field: "Number", HasJSONTag: false, HasDBTag: false},
			want: false,
		},
		{
			name: "PrimaryAccountNumber no DB tag -> false (PAN, excluded)",
			src:  taint.Source{Package: "example.com/domain", TypeName: "Card", Field: "PrimaryAccountNumber", HasJSONTag: false, HasDBTag: false},
			want: false,
		},
		{
			name: "AccountNumber no DB tag -> false (PAN-like, excluded)",
			src:  taint.Source{Package: "example.com/domain", TypeName: "Card", Field: "AccountNumber", HasJSONTag: false, HasDBTag: false},
			want: false,
		},
		{
			name: "CardNumber no DB tag -> false (PAN-like, excluded)",
			src:  taint.Source{Package: "example.com/domain", TypeName: "Card", Field: "CardNumber", HasJSONTag: false, HasDBTag: false},
			want: false,
		},
		{
			name: "CVV with HasDBTag=true -> false (storage model, not inconclusive)",
			src:  taint.Source{Package: "example.com/model", TypeName: "CardDB", Field: "CVV", HasJSONTag: false, HasDBTag: true},
			want: false,
		},
		{
			name: "SecurityCode with HasDBTag=true -> false (storage wins)",
			src:  taint.Source{Package: "example.com/model", TypeName: "CardDB", Field: "SecurityCode", HasJSONTag: false, HasDBTag: true},
			want: false,
		},
		{
			name: "empty field name -> false",
			src:  taint.Source{Package: "example.com/domain", TypeName: "Card", Field: "", HasJSONTag: false, HasDBTag: false},
			want: false,
		},
		{
			name: "unrelated field name -> false",
			src:  taint.Source{Package: "example.com/domain", TypeName: "Card", Field: "Amount", HasJSONTag: false, HasDBTag: false},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := negativeEvidenceTransit(tc.src)
			if got != tc.want {
				t.Errorf("negativeEvidenceTransit(%+v) = %v, want %v", tc.src, got, tc.want)
			}
		})
	}
}
