package keywords

import "testing"

func TestPaymentFuncTier(t *testing.T) {
	tests := []struct {
		name             string
		funcName         string
		fileTier1Present bool
		want             int
	}{
		// Tier 1 keywords: core payment operations.
		{"HandlePayment -> Tier 1", "HandlePayment", false, 1},
		{"ProcessCard -> Tier 1", "ProcessCard", false, 1},
		{"HandleCheckout -> Tier 1", "HandleCheckout", false, 1},
		{"ProcessRefund -> Tier 1", "ProcessRefund", false, 1},
		{"HandleBilling -> Tier 1", "HandleBilling", false, 1},
		{"VaultTokenize -> Tier 1", "VaultTokenize", false, 1},
		{"chargeCustomer -> Tier 1", "chargeCustomer", false, 1},
		{"createTransfer -> Tier 1", "createTransfer", false, 1},
		{"processTransaction -> Tier 1", "processTransaction", false, 1},

		// Tier 2 keywords: payment-adjacent operations.
		{"CreateInvoice -> Tier 2", "CreateInvoice", false, 2},
		{"HandleOrder -> Tier 2", "HandleOrder", false, 2},
		{"ProcessPurchase -> Tier 2", "ProcessPurchase", false, 2},
		{"SettleMerchant -> Tier 2", "SettleMerchant", false, 2},

		// Tier 3 keywords: only with co-location.
		{"HandleCallback with Tier1 -> Tier 3", "HandleCallback", true, 3},
		{"HandleCallback without Tier1 -> 0", "HandleCallback", false, 0},
		{"WebhookHandler with Tier1 -> Tier 3", "WebhookHandler", true, 3},
		{"WebhookHandler without Tier1 -> 0", "WebhookHandler", false, 0},
		{"NotifyUser with Tier1 -> Tier 3", "NotifyUser", true, 3},
		{"NotifyUser without Tier1 -> 0", "NotifyUser", false, 0},

		// Non-payment functions.
		{"GetUserProfile -> 0", "GetUserProfile", false, 0},
		{"ServeHTTP -> 0", "ServeHTTP", false, 0},
		{"HandleHealth -> 0", "HandleHealth", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PaymentFuncTier(tt.funcName, tt.fileTier1Present)
			if got != tt.want {
				t.Errorf("PaymentFuncTier(%q, %v) = %d, want %d",
					tt.funcName, tt.fileTier1Present, got, tt.want)
			}
		})
	}
}

func TestFileHasTier1Keyword(t *testing.T) {
	tests := []struct {
		name      string
		funcNames []string
		want      bool
	}{
		{"has payment handler", []string{"HandlePayment", "HandleHealth"}, true},
		{"has checkout handler", []string{"CheckoutHandler"}, true},
		{"no payment functions", []string{"HandleHealth", "GetUser"}, false},
		{"empty list", []string{}, false},
		{"vault keyword", []string{"VaultStore"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FileHasTier1Keyword(tt.funcNames)
			if got != tt.want {
				t.Errorf("FileHasTier1Keyword(%v) = %v, want %v",
					tt.funcNames, got, tt.want)
			}
		})
	}
}

func TestIsPaymentPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"payment in path", "/api/payment/create", true},
		{"checkout root", "/checkout", true},
		{"users no match", "/api/users", false},
		{"tokenize", "/api/tokenize", true},
		{"vault store", "/api/vault/store", true},
		{"check-out with dash", "/check-out/step1", true},
		{"billing invoices", "/billing/invoices", true},
		{"health no match", "/api/health", false},
		{"cards plural", "/api/cards/list", true},
		{"card singular", "/api/card/create", true},
		{"transactions", "/api/transactions/history", true},
		{"charges", "/api/charges", true},
		{"refunds", "/api/refunds/create", true},
		{"transfers", "/api/transfers", true},
		{"orders", "/api/orders/1", true},
		{"purchases", "/api/purchases", true},
		{"bill singular", "/api/bill/pay", true},
		{"invoice singular", "/api/invoice/123", true},
		{"detokenize", "/api/detokenize", true},
		{"token", "/api/token/refresh", true},
		{"empty path", "", false},
		{"just slash", "/", false},
		{"case insensitive", "/api/PAYMENT/create", true},
		{"partial match should not work", "/api/paymentsomething", false}, // exact segment match
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPaymentPath(tt.path); got != tt.want {
				t.Errorf("IsPaymentPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
