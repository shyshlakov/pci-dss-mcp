package panscanner

import "testing"

func TestLuhnValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid card numbers (known test cards).
		{"Visa test 4111", "4111111111111111", true},
		{"Stripe test", "4242424242424242", true},
		{"Mastercard test 5500", "5500000000000004", true},
		{"Mastercard test 5105", "5105105105105100", true},
		{"Mastercard 2-series", "2223000048410010", true},
		{"Amex test 3782", "378282246310005", true},
		{"Amex test 3714", "371449635398431", true},
		{"Discover test", "6011111111111117", true},
		{"JCB test", "3530111333300000", true},
		{"All zeros", "0000000000000000", true},

		// Invalid checksums.
		{"Bad checksum Visa", "4111111111111112", false},
		{"Bad checksum single digit off", "4111111111111110", false},

		// Edge cases.
		{"Too short", "12345", false},
		{"Non-digit", "abcdef", false},
		{"Empty", "", false},
		{"Mixed alpha-numeric", "4111a11111111111", false},
		{"Spaces (not stripped)", "4111 1111 1111 1111", false},
		{"Hyphens (not stripped)", "4111-1111-1111-1111", false},
		{"Too long (20 digits)", "41111111111111111111", false},
		{"13 digit Visa (Luhn-invalid)", "4222222222225", false},
		{"13 digit Visa valid", "4000000000006", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LuhnValid(tt.input)
			if got != tt.want {
				t.Errorf("LuhnValid(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMatchesIINPrefix(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Visa: starts with 4, len 13, 16, or 19.
		{"Visa 16-digit", "4111111111111111", true},
		{"Visa 13-digit", "4111111111111", true},

		// Mastercard: 51-55 len 16 or 2221-2720 len 16.
		{"MC 55 prefix", "5500000000000004", true},
		{"MC 51 prefix", "5105105105105100", true},
		{"MC 2-series 2223", "2223000048410010", true},
		{"MC 2-series 2221", "2221000000000000", true},
		{"MC 2-series 2720", "2720000000000000", true},
		{"MC 2-series below 2221", "2220000000000000", false},
		{"MC 2-series above 2720", "2721000000000000", false},

		// Amex: 34 or 37, len 15.
		{"Amex 37", "378282246310005", true},
		{"Amex 34", "340000000000009", true},

		// Discover: 6011, 644-649, 65.
		{"Discover 6011", "6011111111111117", true},
		{"Discover 65", "6500000000000002", true},
		{"Discover 644", "6440000000000000", true},
		{"Discover 649", "6490000000000000", true},

		// JCB: 3528-3589.
		{"JCB 3530", "3530111333300000", true},
		{"JCB 3528", "3528000000000000", true},
		{"JCB 3589", "3589000000000000", true},
		{"JCB below 3528", "3527000000000000", false},
		{"JCB above 3589", "3590000000000000", false},

		// No brand match.
		{"All zeros no brand", "0000000000000000", false},
		{"9-prefix no brand", "9111111111111111", false},
		{"Too short", "1234567890", false},
		{"1-prefix 16-digit", "1111111111111111", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesIINPrefix(tt.input)
			if got != tt.want {
				t.Errorf("MatchesIINPrefix(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsLikelyPAN(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Visa valid Luhn + IIN", "4111111111111111", true},
		{"Bad checksum", "4111111111111112", false},
		{"Luhn valid no IIN", "0000000000000000", false},
		{"Non-card string", "hello", false},
		{"Empty", "", false},
		{"Amex valid", "378282246310005", true},
		{"MC 2-series valid", "2223000048410010", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsLikelyPAN(tt.input)
			if got != tt.want {
				t.Errorf("IsLikelyPAN(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractDigits(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"pure digits", "4111111111111111", "4111111111111111"},
		{"dashes", "4111-1111-1111-1111", "4111111111111111"},
		{"spaces", "4111 1111 1111 1111", "4111111111111111"},
		{"mixed separators", "4111.1111-1111 1111", "4111111111111111"},
		{"no digits", "hello", ""},
		{"empty", "", ""},
		{"prefix text", "card=4111111111111111", "4111111111111111"},
		{"quoted", "\"4111111111111111\"", "4111111111111111"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractDigits(tt.input)
			if got != tt.want {
				t.Errorf("ExtractDigits(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
