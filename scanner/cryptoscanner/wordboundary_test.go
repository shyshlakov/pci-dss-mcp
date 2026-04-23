package cryptoscanner

import (
	"reflect"
	"testing"
)

func TestSplitCamelCase(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "simple camelCase - consumerKey",
			input: "consumerKey",
			want:  []string{"consumer", "Key"},
		},
		{
			name:  "three words - signingKeyBase64",
			input: "signingKeyBase64",
			want:  []string{"signing", "Key", "Base64"},
		},
		{
			name:  "multiple words - LogKeyRequestID",
			input: "LogKeyRequestID",
			want:  []string{"Log", "Key", "Request", "ID"},
		},
		{
			name:  "error prefix - ErrTokenTypeNotSupported",
			input: "ErrTokenTypeNotSupported",
			want:  []string{"Err", "Token", "Type", "Not", "Supported"},
		},
		{
			name:  "status suffix - TokenStatusSuspended",
			input: "TokenStatusSuspended",
			want:  []string{"Token", "Status", "Suspended"},
		},
		{
			name:  "simple two words - sharedSecret",
			input: "sharedSecret",
			want:  []string{"shared", "Secret"},
		},
		{
			name:  "acronym prefix - HTTPSKey",
			input: "HTTPSKey",
			want:  []string{"HTTPS", "Key"},
		},
		{
			name:  "acronym suffix - requestID",
			input: "requestID",
			want:  []string{"request", "ID"},
		},
		{
			name:  "single lowercase word - apikey",
			input: "apikey",
			want:  []string{"apikey"},
		},
		{
			name:  "snake_case - consumer_key",
			input: "consumer_key",
			want:  []string{"consumer", "key"},
		},
		{
			name:  "UPPER_SNAKE - API_KEY",
			input: "API_KEY",
			want:  []string{"API", "KEY"},
		},
		{
			name:  "short word - iv",
			input: "iv",
			want:  []string{"iv"},
		},
		{
			name:  "acronym lowercase prefix - aesIV",
			input: "aesIV",
			want:  []string{"aes", "IV"},
		},
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "single uppercase letter - A",
			input: "A",
			want:  []string{"A"},
		},
		{
			name:  "all uppercase - APIKEY",
			input: "APIKEY",
			want:  []string{"APIKEY"},
		},
		{
			name:  "three word acronym end - encryptionKeyPEM",
			input: "encryptionKeyPEM",
			want:  []string{"encryption", "Key", "PEM"},
		},
		{
			name:  "mixed delimiters - consumer-key",
			input: "consumer-key",
			want:  []string{"consumer", "key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitCamelCase(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitCamelCase(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsKeywordAtWordBoundary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		varName string
		keyword string
		want    bool
	}{
		// True positives -- MUST match
		{
			name:    "last word - consumerKey",
			varName: "consumerKey",
			keyword: "key",
			want:    true,
		},
		{
			name:    "followed by value-suffix Base64 - signingKeyBase64",
			varName: "signingKeyBase64",
			keyword: "key",
			want:    true,
		},
		{
			name:    "last word - sharedSecret",
			varName: "sharedSecret",
			keyword: "secret",
			want:    true,
		},
		{
			name:    "followed by value-suffix PEM - encryptionKeyPEM",
			varName: "encryptionKeyPEM",
			keyword: "key",
			want:    true,
		},
		{
			name:    "last word - tokenPassword",
			varName: "tokenPassword",
			keyword: "password",
			want:    true,
		},
		{
			name:    "followed by value-suffix String - apiKeyString",
			varName: "apiKeyString",
			keyword: "key",
			want:    true,
		},
		{
			name:    "followed by value-suffix Value - secretValue",
			varName: "secretValue",
			keyword: "secret",
			want:    true,
		},
		{
			name:    "snake_case last word - consumer_key",
			varName: "consumer_key",
			keyword: "key",
			want:    true,
		},
		{
			name:    "UPPER_SNAKE case-insensitive - API_KEY",
			varName: "API_KEY",
			keyword: "key",
			want:    true,
		},
		{
			name:    "compound keyword exact match - apikey",
			varName: "apikey",
			keyword: "apikey",
			want:    true,
		},
		{
			name:    "followed by value-suffix Bytes - tokenBytes",
			varName: "tokenBytes",
			keyword: "token",
			want:    true,
		},
		{
			name:    "followed by value-suffix Data - secretData",
			varName: "secretData",
			keyword: "secret",
			want:    true,
		},
		{
			name:    "followed by value-suffix File - keyFile",
			varName: "keyFile",
			keyword: "key",
			want:    true,
		},
		{
			name:    "followed by value-suffix Path - keyPath",
			varName: "keyPath",
			keyword: "key",
			want:    true,
		},
		{
			name:    "followed by value-suffix Dir - secretDir",
			varName: "secretDir",
			keyword: "secret",
			want:    true,
		},
		{
			name:    "followed by value-suffix Encoded - tokenEncoded",
			varName: "tokenEncoded",
			keyword: "token",
			want:    true,
		},
		{
			name:    "followed by value-suffix JWE - keyJWE",
			varName: "keyJWE",
			keyword: "key",
			want:    true,
		},

		// False positives -- MUST NOT match
		{
			name:    "followed by Request - LogKeyRequestID",
			varName: "LogKeyRequestID",
			keyword: "key",
			want:    false,
		},
		{
			name:    "followed by Type - ErrTokenTypeNotSupported",
			varName: "ErrTokenTypeNotSupported",
			keyword: "token",
			want:    false,
		},
		{
			name:    "followed by Status - TokenStatusSuspended",
			varName: "TokenStatusSuspended",
			keyword: "token",
			want:    false,
		},
		{
			name:    "keyword prefix of word - keyboardLayout",
			varName: "keyboardLayout",
			keyword: "key",
			want:    false,
		},
		{
			name:    "keyword not present - bucketName",
			varName: "bucketName",
			keyword: "token",
			want:    false,
		},
		{
			name:    "keyword embedded in word - monkeyPatch",
			varName: "monkeyPatch",
			keyword: "key",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsKeywordAtWordBoundary(tt.varName, tt.keyword)
			if got != tt.want {
				t.Errorf("IsKeywordAtWordBoundary(%q, %q) = %v, want %v", tt.varName, tt.keyword, got, tt.want)
			}
		})
	}
}

func TestIsKeywordAtWordBoundaryAllKeywords(t *testing.T) {
	t.Parallel()
	// Verify all keyRelatedKeywords work with the boundary function.
	// Each keyword should match when it's the last word of a varName.
	for _, kw := range keyRelatedKeywords {
		varName := "test" + capitalize(kw)
		if !IsKeywordAtWordBoundary(varName, kw) {
			t.Errorf("IsKeywordAtWordBoundary(%q, %q) = false, want true (keyword as last word)", varName, kw)
		}
	}
}

// capitalize returns s with first letter uppercased for building test variable names.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] -= 32
	}
	return string(r)
}
