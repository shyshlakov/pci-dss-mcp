// Package tlsscanner implements the TLS configuration scanner that detects
// InsecureSkipVerify, weak MinVersion, missing MinVersion, and prohibited
// cipher suites in tls.Config composite literals and field assignments.
//
// Detection rules:
// - TLS-INSECURE-SKIP-VERIFY: InsecureSkipVerify set to true (4.2.1)
// - TLS-WEAK-VERSION: MinVersion below TLS 1.2 (4.2.1)
// - TLS-MISSING-MIN-VERSION: tls.Config without MinVersion field (4.2.1)
// - TLS-WEAK-CIPHER: Prohibited cipher suites -- RC4, 3DES, NULL, EXPORT, anon (4.2.1)
package tlsscanner

import "strings"

// prohibitedCipherSubstrings contains substrings that indicate a cipher suite
// is prohibited per PCI DSS 4.2.1. Matched case-insensitively against cipher
// constant names (e.g., TLS_RSA_WITH_RC4_128_SHA).
//
// Note: "DES_" is NOT used because it would false-match "3DES_EDE"; instead
// "3DES" specifically targets triple-DES which is the only DES variant
// exposed in Go's crypto/tls package.
var prohibitedCipherSubstrings = []string{
	"RC4",
	"3DES",
	"NULL",
	"EXPORT",
	"ANON",
}

// isProhibitedCipher checks if a cipher suite constant name contains any
// prohibited substring. The check is case-insensitive.
func isProhibitedCipher(constantName string) bool {
	upper := strings.ToUpper(constantName)
	for _, sub := range prohibitedCipherSubstrings {
		if strings.Contains(upper, sub) {
			return true
		}
	}
	return false
}

// weakTLSVersions maps Go crypto/tls version constant names to weak status.
// VersionSSL30, VersionTLS10, and VersionTLS11 are considered weak per PCI DSS 4.2.1.
// VersionTLS12 and VersionTLS13 are acceptable.
var weakTLSVersions = map[string]bool{
	"VersionSSL30": true,
	"VersionTLS10": true,
	"VersionTLS11": true,
}

// isWeakTLSVersion checks if a TLS version constant name represents a weak version.
func isWeakTLSVersion(constantName string) bool {
	return weakTLSVersions[constantName]
}
