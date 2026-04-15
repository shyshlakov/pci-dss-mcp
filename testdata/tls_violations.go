//go:build ignore

// Package testdata contains test fixtures for PCI DSS compliance scanning.
// This file contains INTENTIONAL TLS configuration violations for testing. DO NOT use as example code.
package testdata

import (
	"crypto/tls"
	"net/http"
)

// --- TLS-INSECURE-SKIP-VERIFY violations (TLS-01) ---

// VIOLATION: TLS-INSECURE-SKIP-VERIFY CRITICAL - InsecureSkipVerify set to true in composite literal (4.2.1)
var insecureClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

// VIOLATION: TLS-MISSING-MIN-VERSION HIGH - tls.Config without MinVersion (4.2.1)
// (The tls.Config above also has no MinVersion)

// VIOLATION: TLS-INSECURE-SKIP-VERIFY CRITICAL - InsecureSkipVerify via field assignment (4.2.1)
func makeInsecureTransport() *http.Transport {
	cfg := &tls.Config{}
	cfg.InsecureSkipVerify = true
	return &http.Transport{TLSClientConfig: cfg}
}

// --- TLS-WEAK-VERSION violations (TLS-02) ---

// VIOLATION: TLS-WEAK-VERSION CRITICAL - MinVersion set to TLS 1.0 (4.2.1)
var weakTLS10 = &tls.Config{
	MinVersion: tls.VersionTLS10,
}

// VIOLATION: TLS-WEAK-VERSION CRITICAL - MinVersion set to TLS 1.1 (4.2.1)
var weakTLS11 = &tls.Config{
	MinVersion: tls.VersionTLS11,
}

// VIOLATION: TLS-WEAK-VERSION CRITICAL - MinVersion set to SSL 3.0 (4.2.1)
var weakSSL30 = &tls.Config{
	MinVersion: tls.VersionSSL30,
}

// --- TLS-MISSING-MIN-VERSION violations ---

// VIOLATION: TLS-MISSING-MIN-VERSION HIGH - empty tls.Config without MinVersion (4.2.1)
var emptyConfig = &tls.Config{}

// --- TLS-WEAK-CIPHER violations (TLS-03) ---

// VIOLATION: TLS-WEAK-CIPHER CRITICAL - RC4 cipher suite (4.2.1)
// VIOLATION: TLS-WEAK-CIPHER CRITICAL - 3DES cipher suite (4.2.1)
var weakCipherConfig = &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	},
}

// --- NO VIOLATION: secure configuration ---

var secureConfig = &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	},
}

// NO VIOLATION: TLS 1.3 is acceptable
var secureTLS13 = &tls.Config{
	MinVersion: tls.VersionTLS13,
}

// NO VIOLATION: InsecureSkipVerify explicitly set to false
var explicitSecure = &tls.Config{
	InsecureSkipVerify: false,
	MinVersion:         tls.VersionTLS12,
}

// Ensure variables are used to prevent compilation errors.
func init() {
	_ = insecureClient
	_ = weakTLS10
	_ = weakTLS11
	_ = weakSSL30
	_ = emptyConfig
	_ = weakCipherConfig
	_ = secureConfig
	_ = secureTLS13
	_ = explicitSecure
}
