package analysis

import "testing"

func TestIsSensitiveFieldName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want bool
	}{
		{"cardNumber", true},
		{"panData", true},
		{"cvvCache", true},
		{"userName", false},
		{"address", false},
		{"PaymentInfo", true},
		{"auth_data_field", true},
		{"CreditCardToken", true},
		{"PINBlock", true},
		{"trackData", true},
		{"cardholder_name", true},
		{"sensitiveInfo", true},
		{"email", false},
		{"age", false},
		{"accountnumber_hash", true},
		{"debitcard_last4", true},
		// "sad" keyword: SAD = Sensitive Authentication Data
		{"sadField", true},
		// Edge: empty string.
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSensitiveFieldName(tt.name)
			if got != tt.want {
				t.Errorf("IsSensitiveFieldName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsSensitiveVarName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want bool
	}{
		{"cardNumber", true},
		{"panData", true},
		{"cvvCache", true},
		{"userName", false},
		{"address", false},
		{"PaymentInfo", true},
		{"auth_data_field", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSensitiveVarName(tt.name)
			if got != tt.want {
				t.Errorf("IsSensitiveVarName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
