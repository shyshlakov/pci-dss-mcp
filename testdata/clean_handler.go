// Package testdata contains test fixtures for PCI DSS compliance scanning.
// This file represents a clean payment handler with no violations.
package testdata

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
)

// PaymentRequest represents an incoming payment request with masked data.
type PaymentRequest struct {
	TokenizedCard string `json:"tokenized_card"` // tokenized, not raw PAN
	Amount        int    `json:"amount"`
	Currency      string `json:"currency"`
}

// PaymentResponse is returned to the client after processing.
type PaymentResponse struct {
	TransactionID string `json:"transaction_id"`
	Status        string `json:"status"`
}

// HandlePayment processes a payment request securely.
// It uses tokenized card data, never logs sensitive values,
// and returns only safe information to the client.
func HandlePayment(w http.ResponseWriter, r *http.Request) {
	var req PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Return a generic error without internal details.
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Log the event without sensitive data.
	slog.Info("payment_received",
		"amount", req.Amount,
		"currency", req.Currency,
	)

	txID, err := generateTransactionID()
	if err != nil {
		slog.Error("failed to generate transaction ID", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := PaymentResponse{
		TransactionID: txID,
		Status:        "processed",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

// generateTransactionID creates a cryptographically random transaction ID.
func generateTransactionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:16]), nil
}
