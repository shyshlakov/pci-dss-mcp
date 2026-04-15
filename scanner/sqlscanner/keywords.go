// Package sqlscanner detects sensitive cardholder columns in SQL schema files
// and Go gorm/db/sql struct tags that persist PAN/SAD without application-level
// encryption. The sensitive keyword list is reused from panscanner — do NOT
// duplicate it here.
//
// The scanner uses context-aware matching: broadened keywords (number, account
// code, verification) are gated behind isCardContextTable to prevent FPs on
// non-card tables. Expiry keywords only fire when PAN is unprotected.
package sqlscanner

import (
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
)

// cardContextKeywords are column names sensitive ONLY in card/payment table context.
var cardContextKeywords = map[string]bool{
	"number":       true,
	"account":      true,
	"code":         true,
	"verification": true,
}

// expiryKeywords are column names sensitive ONLY when PAN is unprotected.
var expiryKeywords = map[string]bool{
	"expmonth":        true,
	"expyear":         true,
	"expirationmonth": true,
	"expirationyear":  true,
	"month":           true,
	"year":            true,
}

// sqlExpiryColumns are raw SQL column names that represent expiration date fields.
// Per PCI DSS 3.3.1.1, expiration date is cardholder data (NOT SAD) and is
// allowed to be stored when PAN is rendered unreadable per 3.5.1.
// Used by scanSQLFile to suppress exp_date findings when PAN is protected.
var sqlExpiryColumns = map[string]bool{
	"exp_month":        true,
	"exp_year":         true,
	"expiration_month": true,
	"expiration_year":  true,
	"exp_date":         true,
	"expiration_date":  true,
}

// IsSQLExpiryColumn reports whether name (a raw SQL column name) is an
// expiration date column. Input is lowercased and unquoted before lookup.
func IsSQLExpiryColumn(name string) bool {
	norm := strings.ToLower(strings.Trim(name, `"`+"`"))
	return sqlExpiryColumns[norm]
}

// cardContextTableKeywords are normalized table name substrings indicating card/payment context.
var cardContextTableKeywords = []string{
	"card", "cards", "creditcard", "creditcards", "debitcard", "debitcards",
	"paymentmethod", "paymentmethods", "token", "tokens", "vault", "wallet",
}

// isCardContextTable returns true if the normalized table name contains a card/payment keyword.
func isCardContextTable(name string) bool {
	norm := panscanner.Normalize(name)
	for _, kw := range cardContextTableKeywords {
		if strings.Contains(norm, kw) {
			return true
		}
	}
	return false
}

// isSensitiveColumn reports whether a SQL column name or gorm tag value maps
// to one of the 18 panscanner cardholder-data keywords after normalization
// (case-insensitive, underscores/hyphens stripped).
func isSensitiveColumn(name string) bool {
	return panscanner.IsSensitiveKeyword(name)
}

// isSensitiveColumnInContext reports whether a column is sensitive given its
// table context and PAN protection status.
//
// Rule 1: global panscanner keywords always match regardless of table.
// Rule 2: cardContextKeywords match ONLY in card/payment tables.
// Rule 3: expiryKeywords match ONLY in card/payment tables AND when panProtected=false.
func isSensitiveColumnInContext(tableName, columnName string, panProtected bool) bool {
	// Rule 1: global panscanner keywords always match regardless of table.
	if panscanner.IsSensitiveKeyword(columnName) {
		return true
	}

	// Rules 2 and 3 require card-context table.
	if !isCardContextTable(tableName) {
		return false
	}

	normCol := panscanner.Normalize(columnName)

	// Rule 2: context keywords match in card tables.
	if cardContextKeywords[normCol] {
		return true
	}

	// Rule 3: expiry keywords match only when PAN is unprotected.
	if !panProtected && expiryKeywords[normCol] {
		return true
	}

	return false
}
