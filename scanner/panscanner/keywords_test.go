package panscanner

import "testing"

func TestNormalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"card_number", "cardnumber"},
		{"CardNumber", "cardnumber"},
		{"CARD_NUMBER", "cardnumber"},
		{"card-number", "cardnumber"},
		{"cardNumber", "cardnumber"},
		{"pan", "pan"},
		{"PAN", "pan"},
		{"cvv", "cvv"},
		{"CVV", "cvv"},
		{"credit_card", "creditcard"},
		{"CREDIT-CARD", "creditcard"},
		{"", ""},
		{"simple", "simple"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := Normalize(tt.input)
			if got != tt.want {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsSensitiveKeyword(t *testing.T) {
	t.Parallel()
	// All 18 keywords from must match (various casings/separators).
	positives := []string{
		"pan", "PAN", "Pan",
		"cvv", "CVV", "Cvv",
		"cvc", "CVC",
		"cardNumber", "card_number", "CardNumber", "CARD_NUMBER", "card-number",
		"cardNum", "card_num", "CardNum",
		"creditCard", "credit_card", "CreditCard", "CREDIT_CARD",
		"debitCard", "debit_card", "DebitCard",
		"accountNumber", "account_number", "AccountNumber",
		"expiry", "Expiry", "EXPIRY",
		"primaryAccountNumber", "primary_account_number", "PrimaryAccountNumber",
		"securityCode", "security_code", "SecurityCode",
		"verificationCode", "verification_code", "VerificationCode",
		"cardHolder", "card_holder", "CardHolder",
		"trackData", "track_data", "TrackData",
		"track1", "Track1", "TRACK1",
		"track2", "Track2", "TRACK2",
		"magneticStripe", "magnetic_stripe", "MagneticStripe",
		"pinBlock", "pin_block", "PinBlock",
	}
	for _, name := range positives {
		t.Run("positive_"+name, func(t *testing.T) {
			if !IsSensitiveKeyword(name) {
				t.Errorf("IsSensitiveKeyword(%q) = false, want true", name)
			}
		})
	}

	// False positives -- must NOT match.
	negatives := []string{
		"panel",
		"span",
		"expand",
		"panning",
		"company",
		"japan",
		"username",
		"password",
		"amount",
		"currency",
		"handler",
		"",
	}
	for _, name := range negatives {
		t.Run("negative_"+name, func(t *testing.T) {
			if IsSensitiveKeyword(name) {
				t.Errorf("IsSensitiveKeyword(%q) = true, want false", name)
			}
		})
	}
}

func TestHasTestPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  bool
	}{
		{"testCardNumber", true},
		{"mockCVV", true},
		{"fakeCard", true},
		{"dummyPAN", true},
		{"stubPayment", true},
		{"TestCardNumber", true},
		{"TESTPAN", true},
		{"cardNumber", false},
		{"", false},
		{"testing", true},
		{"production", false},
		{"attestation", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := HasTestPrefix(tt.input)
			if got != tt.want {
				t.Errorf("HasTestPrefix(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
