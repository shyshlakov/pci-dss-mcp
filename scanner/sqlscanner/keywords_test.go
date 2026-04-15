package sqlscanner

import "testing"

// TestIsCardContextTable verifies card/payment table detection.
func TestIsCardContextTable(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"cards", true},
		{"credit_cards", true},
		{"debit_cards", true},
		{"payment_methods", true},
		{"tokens", true},
		{"vault", true},
		{"wallet", true},
		{"users", false},
		{"orders", false},
		{"subscriptions", false},
		{"sessions", false},
		{"card_events", true}, // contains "card"
		{"token_vault", true}, // contains "token" and "vault"
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := isCardContextTable(tc.name); got != tc.want {
				t.Errorf("isCardContextTable(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestIsSensitiveColumnInContext verifies context-aware column matching.
func TestIsSensitiveColumnInContext(t *testing.T) {
	tests := []struct {
		name         string
		tableName    string
		columnName   string
		panProtected bool
		want         bool
	}{
		// Rule 1: global panscanner keywords always match
		{"global_cvv_in_cards", "cards", "cvv", false, true},
		{"global_cvv_in_users", "users", "cvv", false, true},
		{"global_pan_anywhere", "events", "pan", false, true},
		{"global_card_number", "cards", "card_number", false, true},

		// Rule 2: context keywords match only in card tables
		{"context_number_in_cards", "cards", "number", false, true},
		{"context_number_in_users", "users", "number", false, false},
		{"context_account_in_payment_methods", "payment_methods", "account", false, true},
		{"context_account_in_orders", "orders", "account", false, false},
		{"context_code_in_cards", "cards", "code", false, true},
		{"context_verification_in_cards", "cards", "verification", false, true},
		{"context_number_in_tokens", "tokens", "number", false, true},

		// Rule 3: expiry keywords match only in card tables AND when panProtected=false
		{"expiry_exp_month_cards_unprotected", "cards", "exp_month", false, true},
		{"expiry_exp_month_cards_protected", "cards", "exp_month", true, false},
		{"expiry_exp_year_cards_unprotected", "cards", "exp_year", false, true},
		{"expiry_exp_year_cards_protected", "cards", "exp_year", true, false},
		{"expiry_month_cards_unprotected", "cards", "month", false, true},
		{"expiry_month_orders_unprotected", "orders", "month", false, false},

		// Edge cases
		{"empty_table", "", "number", false, false},
		{"empty_column", "cards", "", false, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := isSensitiveColumnInContext(tc.tableName, tc.columnName, tc.panProtected); got != tc.want {
				t.Errorf("isSensitiveColumnInContext(%q, %q, %v) = %v, want %v",
					tc.tableName, tc.columnName, tc.panProtected, got, tc.want)
			}
		})
	}
}
