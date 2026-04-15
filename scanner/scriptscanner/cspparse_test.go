package scriptscanner

import "testing"

func TestParseCSP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  CSPAnalysis
	}{
		{
			name:  "basic CSP with script-src self and external",
			input: "default-src 'self'; script-src 'self' https://cdn.example.com",
			want: CSPAnalysis{
				HasScriptSrc:        true,
				HasDefaultSrc:       true,
				NoScriptRestriction: false,
				HasUnsafeInline:     false,
				HasUnsafeEval:       false,
				HasNonce:            false,
				HasStrictDynamic:    false,
				ValueAnalyzable:     true,
			},
		},
		{
			name:  "script-src with unsafe-inline and unsafe-eval",
			input: "script-src 'unsafe-inline' 'unsafe-eval'",
			want: CSPAnalysis{
				HasScriptSrc:        true,
				HasDefaultSrc:       false,
				NoScriptRestriction: false,
				HasUnsafeInline:     true,
				HasUnsafeEval:       true,
				HasNonce:            false,
				HasStrictDynamic:    false,
				ValueAnalyzable:     true,
			},
		},
		{
			name:  "nonce overrides unsafe-inline per CSP3",
			input: "script-src 'nonce-abc123' 'unsafe-inline'",
			want: CSPAnalysis{
				HasScriptSrc:        true,
				HasDefaultSrc:       false,
				NoScriptRestriction: false,
				HasUnsafeInline:     false, // CSP3: nonce overrides unsafe-inline
				HasUnsafeEval:       false,
				HasNonce:            true,
				HasStrictDynamic:    false,
				ValueAnalyzable:     true,
			},
		},
		{
			name:  "strict-dynamic overrides unsafe-inline per CSP3",
			input: "script-src 'strict-dynamic' 'unsafe-inline'",
			want: CSPAnalysis{
				HasScriptSrc:        true,
				HasDefaultSrc:       false,
				NoScriptRestriction: false,
				HasUnsafeInline:     false, // CSP3: strict-dynamic overrides unsafe-inline
				HasUnsafeEval:       false,
				HasNonce:            false,
				HasStrictDynamic:    true,
				ValueAnalyzable:     true,
			},
		},
		{
			name:  "default-src fallback when no script-src",
			input: "default-src 'self' 'unsafe-inline'",
			want: CSPAnalysis{
				HasScriptSrc:        false,
				HasDefaultSrc:       true,
				NoScriptRestriction: false,
				HasUnsafeInline:     true,
				HasUnsafeEval:       false,
				HasNonce:            false,
				HasStrictDynamic:    false,
				ValueAnalyzable:     true,
			},
		},
		{
			name:  "no script-src and no default-src means no restriction",
			input: "img-src *; font-src *",
			want: CSPAnalysis{
				HasScriptSrc:        false,
				HasDefaultSrc:       false,
				NoScriptRestriction: true,
				HasUnsafeInline:     false,
				HasUnsafeEval:       false,
				HasNonce:            false,
				HasStrictDynamic:    false,
				ValueAnalyzable:     true,
			},
		},
		{
			name:  "nonce overrides unsafe-inline but NOT unsafe-eval",
			input: "script-src 'nonce-abc' 'unsafe-eval'",
			want: CSPAnalysis{
				HasScriptSrc:        true,
				HasDefaultSrc:       false,
				NoScriptRestriction: false,
				HasUnsafeInline:     false,
				HasUnsafeEval:       true, // nonce does NOT override unsafe-eval
				HasNonce:            true,
				HasStrictDynamic:    false,
				ValueAnalyzable:     true,
			},
		},
		{
			name:  "case-insensitive directive names",
			input: "Script-Src 'UNSAFE-INLINE'",
			want: CSPAnalysis{
				HasScriptSrc:        true,
				HasDefaultSrc:       false,
				NoScriptRestriction: false,
				HasUnsafeInline:     true,
				HasUnsafeEval:       false,
				HasNonce:            false,
				HasStrictDynamic:    false,
				ValueAnalyzable:     true,
			},
		},
		{
			name:  "empty string",
			input: "",
			want: CSPAnalysis{
				HasScriptSrc:        false,
				HasDefaultSrc:       false,
				NoScriptRestriction: true,
				HasUnsafeInline:     false,
				HasUnsafeEval:       false,
				HasNonce:            false,
				HasStrictDynamic:    false,
				ValueAnalyzable:     true,
			},
		},
		{
			name:  "script-src self only is safe",
			input: "script-src 'self'",
			want: CSPAnalysis{
				HasScriptSrc:        true,
				HasDefaultSrc:       false,
				NoScriptRestriction: false,
				HasUnsafeInline:     false,
				HasUnsafeEval:       false,
				HasNonce:            false,
				HasStrictDynamic:    false,
				ValueAnalyzable:     true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCSP(tt.input)
			if got != tt.want {
				t.Errorf("parseCSP(%q)\n  got:  %+v\n  want: %+v", tt.input, got, tt.want)
			}
		})
	}
}
