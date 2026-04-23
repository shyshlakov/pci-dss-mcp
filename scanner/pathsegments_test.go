package scanner

import "testing"

func TestHasTestDirSegment(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name string
		root string
		path string
		want bool
	}{
		{"test_segment_positive", "/tmp/root", "/tmp/root/internal/test/helper.go", true},
		{"testing_segment_positive", "/tmp/root", "/tmp/root/pkg/testing/mock.go", true},
		{"mocks_segment_positive", "/tmp/root", "/tmp/root/internal/mocks/api.go", true},
		{"fixtures_segment_positive", "/tmp/root", "/tmp/root/pkg/fixtures/data.go", true},
		{"e2e_segment_positive", "/tmp/root", "/tmp/root/internal/e2e/scenario.go", true},
		{"testdata_negative_D02", "/tmp/root", "/tmp/root/testdata/fixture/foo.go", false},
		{"integration_negative_D03", "/tmp/root", "/tmp/root/internal/integration/stripe.go", false},
		{"integrations_negative_D03", "/tmp/root", "/tmp/root/pkg/integrations/visa.go", false},
		{"int_negative_D03", "/tmp/root", "/tmp/root/pkg/int/helper.go", false},
		{"testutil_negative", "/tmp/root", "/tmp/root/pkg/testutil/db.go", false},
		{"case_sensitive_Test_negative", "/tmp/root", "/tmp/root/internal/Test/foo.go", false},
		{"substring_not_segment_negative", "/tmp/root", "/tmp/root/my-test-dir/src/foo.go", false},
		{"nested_test_segment", "/tmp/root", "/tmp/root/a/b/c/test/helper.go", true},
		{"nested_e2e_deep", "/tmp/root", "/tmp/root/clean/test_dir_exclusion/internal/test/e2e/mock_data.go", true},
		{"root_segment_itself", "/tmp/root", "/tmp/root/test/helper.go", true},
		{"empty_root_fallback", "", "internal/test/helper.go", true},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasTestDirSegment(tc.root, tc.path); got != tc.want {
				t.Fatalf("hasTestDirSegment(%q, %q) = %v, want %v", tc.root, tc.path, got, tc.want)
			}
		})
	}
}
