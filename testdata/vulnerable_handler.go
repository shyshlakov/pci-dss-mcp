// Package testdata contains test fixtures for PCI DSS compliance scanning.
// This file contains INTENTIONAL violations for testing. DO NOT use as example code.
package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
)

// VulnerablePayment contains fields that violate PCI DSS naming conventions.
type VulnerablePayment struct {
	cardNumber string // VIOLATION: PAN-001 - PAN in variable name (3.3.1)
	cvv        string // VIOLATION: PAN-002 - CVV stored as string (3.3.1)
	Amount     int
	ExpiryDate string
}

// hardcodedTestCard is a test card number embedded directly in source.
var hardcodedTestCard = "4111111111111111" // VIOLATION: PAN-003 - hardcoded test card number (3.4.1)

// dbPassword is a hardcoded database credential.
var dbPassword = "super_secret_db_pass_123" // VIOLATION: SEC-001 - hardcoded password (8.3.1)

// HandleVulnerablePayment demonstrates multiple PCI DSS violations in a single handler.
func HandleVulnerablePayment(w http.ResponseWriter, r *http.Request) {
	cardNumber := r.FormValue("card_number") // VIOLATION: PAN-004 - PAN in local variable name

	// VIOLATION: PAN-005 - logging card number via fmt.Printf (3.3.1)
	fmt.Printf("Processing payment for card: %s\n", cardNumber)

	// VIOLATION: AUTH-001 - hardcoded password in connection string (8.3.1)
	db, err := sql.Open("postgres", "host=localhost user=admin password=admin123 dbname=payments")
	if err != nil {
		// VIOLATION: ERR-001 - exposing internal error details to HTTP response (6.2.4)
		http.Error(w, fmt.Sprintf("Database connection failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// VIOLATION: DATA-001 - storing PAN in database without encryption (3.4.1)
	_, err = db.Exec("INSERT INTO payments (card_number, amount) VALUES ($1, $2)", cardNumber, 100)
	if err != nil {
		// VIOLATION: ERR-002 - exposing SQL error to client (6.2.4)
		http.Error(w, fmt.Sprintf("Insert failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Use hardcodedTestCard to ensure it's referenced (prevents unused variable).
	_ = hardcodedTestCard
	_ = dbPassword

	fmt.Fprintf(w, "Payment processed for card ending in %s", cardNumber[len(cardNumber)-4:])
}
