package cryptoscanner

import (
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestApplyHardcodedFilter(t *testing.T) {
	tests := []struct {
		name     string
		finding  scanner.Finding
		varName  string
		strVal   string
		initExpr string
		wantSev  scanner.Severity
		wantHint string
	}{
		{
			name:    "Layer0_short_string_INFO",
			finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, FilePath: "internal/auth.go"},
			varName: "secretKey", strVal: "short12345",
			wantSev: scanner.SeverityInfo,
		},
		{
			name:     "Layer1_errors_New_sentinel",
			finding:  scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, FilePath: "internal/errors.go"},
			varName:  "ErrInvalidToken", strVal: "token has expired and cannot be refreshed",
			initExpr: "errors.New",
			wantSev:  scanner.SeverityInfo, wantHint: "hardcoded_sentinel_error",
		},
		{
			name:     "Layer1_fmt_Errorf_sentinel",
			finding:  scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, FilePath: "internal/errors.go"},
			varName:  "ErrMissingKey", strVal: "missing encryption key for request %s",
			initExpr: "fmt.Errorf",
			wantSev:  scanner.SeverityInfo, wantHint: "hardcoded_sentinel_error",
		},
		{
			name:    "Layer2_header_pattern",
			finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, FilePath: "internal/http/headers.go"},
			varName: "authTokenKey", strVal: "X-Auth-Token-Key",
			wantSev: scanner.SeverityInfo, wantHint: "hardcoded_header_name",
		},
		{
			name:    "Layer2_snake_case_log_field",
			finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, FilePath: "internal/logger/fields.go"},
			varName: "logFieldKey", strVal: "secret_request_identifier",
			wantSev: scanner.SeverityInfo, wantHint: "hardcoded_log_field",
		},
		{
			name:    "Layer2_camelCase_json_key",
			finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, FilePath: "internal/api/fields.go"},
			varName: "tokenFieldKey", strVal: "AccessTokenField",
			wantSev: scanner.SeverityInfo, wantHint: "hardcoded_json_key",
		},
		{
			name:    "Layer2_camelCase_high_entropy_NOT_filtered",
			finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, FilePath: "internal/api/fields.go"},
			varName: "tokenFieldKey", strVal: "zX9vQm2tL8jKrB4n",
			wantSev: scanner.SeverityCritical,
		},
		{
			name:    "Layer3_hex_fast_path_CRITICAL",
			finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityHigh, FilePath: "internal/crypto/keys.go"},
			varName: "aes256HexKey", strVal: "4a6f686e446f65313233343536373839306162636465666768696a6b6c6d6e6f",
			wantSev: scanner.SeverityCritical,
		},
		{
			name:    "Layer3_base64_CRITICAL",
			finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityHigh, FilePath: "internal/crypto/keys.go"},
			varName: "signingKeyBase64", strVal: "SGVsbG9Xb3JsZDEyMzQ1Njc4OTA=",
			wantSev: scanner.SeverityCritical,
		},
		{
			name:    "Layer4_constants_file_path_downgrade",
			finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, FilePath: "internal/config/constants.go"},
			varName: "defaultApiKey", strVal: "default-placeholder-val",
			wantSev: scanner.SeverityHigh, wantHint: "crypto_key_constants_file",
		},
		{
			name:    "Layer4_errors_file_path_downgrade",
			finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, FilePath: "internal/errors.go"},
			varName: "defaultSecretKey", strVal: "some-default-value-here",
			wantSev: scanner.SeverityHigh, wantHint: "crypto_key_constants_file",
		},
		{
			name:    "no_filter_genuine_secret",
			finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, FilePath: "internal/auth/admin.go"},
			varName: "adminSecretKey", strVal: "supersecretadminpassword123",
			wantSev: scanner.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ApplyHardcodedFilter(tt.finding, tt.varName, tt.strVal, tt.initExpr)
			if result.Severity != tt.wantSev {
				t.Errorf("Severity = %q, want %q", result.Severity, tt.wantSev)
			}
			if tt.wantHint != "" && result.TriageHint != tt.wantHint {
				t.Errorf("TriageHint = %q, want %q", result.TriageHint, tt.wantHint)
			}
		})
	}
}
