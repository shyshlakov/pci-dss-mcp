package sensitivedata

import "testing"

func TestClassify(t *testing.T) {
	tt := []struct {
		name string
		in   string
		want Kind
	}{
		{"empty", "", KindUnknown},

		{"pan_lower", "pan", KindPAN},
		{"PAN_upper", "PAN", KindPAN},
		{"cardNumber_camel", "cardNumber", KindPAN},
		{"card_number_snake", "card_number", KindPAN},
		{"primary_account_number", "primary_account_number", KindPAN},
		{"ccNo", "ccNo", KindPAN},
		{"cardNo", "cardNo", KindPAN},
		{"primaryAccountNumber", "primaryAccountNumber", KindPAN},
		{"AccountNumber", "AccountNumber", KindPAN},

		{"cvv", "cvv", KindSAD},
		{"CVV2", "CVV2", KindSAD},
		{"cvc", "cvc", KindSAD},
		{"cvc2", "cvc2", KindSAD},
		{"cid", "cid", KindSAD},
		{"card_verification", "card_verification", KindSAD},
		{"security_code_snake", "security_code", KindSAD},
		{"securityCode_camel", "securityCode", KindSAD},
		{"track1", "track1", KindSAD},
		{"track2", "track2", KindSAD},
		{"trackData_camel", "trackData", KindSAD},
		{"track1Data_camel_digit", "track1Data", KindSAD},
		{"track_Data_space", "track Data", KindSAD},
		{"track1_data_snake", "track1_data", KindSAD},
		{"track_data_no_digit", "track_data", KindSAD},
		{"magstripe", "magstripe", KindSAD},
		{"pin_lower", "pin", KindSAD},
		{"pinBlock_camel", "pinBlock", KindSAD},
		{"pin_block_snake", "pin_block", KindSAD},
		{"encrypted_pin", "encrypted_pin", KindSAD},

		{"userId_negative", "userId", KindUnknown},
		{"timestamp_negative", "timestamp", KindUnknown},
		{"myField_negative", "myField", KindUnknown},
		{"companyPin_boundary", "companyPin", KindUnknown},
		{"panel_boundary", "panel", KindUnknown},
		{"cvvCardNumber_camel_no_boundary", "cvvCardNumber", KindUnknown},
		{"pan_number_underscore_no_boundary", "pan_number", KindUnknown},
	}
	for _, c := range tt {
		t.Run(c.name, func(t *testing.T) {
			got := Classify(c.in)
			if got != c.want {
				t.Errorf("Classify(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
