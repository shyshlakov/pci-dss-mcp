//go:build ignore

// Package testdata contains test fixtures for PCI DSS compliance scanning.
// This file contains INTENTIONAL encryption violations for testing. DO NOT use as example code.
package testdata

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
)

// --- CRYPTO-01 violations (weak hash algorithms) ---

// VIOLATION: CRYPTO-WEAK-HASH CRITICAL - md5 near password keyword
func hashPassword(password string) []byte {
	h := md5.New() // VIOLATION: CRYPTO-WEAK-HASH CRITICAL
	h.Write([]byte(password))
	return h.Sum(nil)
}

// VIOLATION: CRYPTO-WEAK-HASH INFO - sha1 without sensitive context
func checksumData(data []byte) []byte {
	sum := sha1.Sum(data) // VIOLATION: CRYPTO-WEAK-HASH INFO
	return sum[:]
}

// VIOLATION: CRYPTO-WEAK-HASH CRITICAL - sha256 near password keyword
func hashUserPasswd(passwd string) [32]byte {
	return sha256.Sum256([]byte(passwd)) // VIOLATION: CRYPTO-WEAK-HASH CRITICAL
}

// NO VIOLATION: sha256 for data checksum (no password context)
func checksumFile(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// --- CRYPTO-02 violations (hardcoded keys) ---

// VIOLATION: CRYPTO-HARDCODED-KEY CRITICAL - keyword "secret" + literal
var secretKey = "mysupersecretkey123"

// VIOLATION: CRYPTO-HARDCODED-KEY HIGH - high entropy string
var apiConfig = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"

// VIOLATION: CRYPTO-HARDCODED-KEY HIGH - base64 encoded blob
var encodedData = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY"

// VIOLATION: CRYPTO-HARDCODED-KEY HIGH - hex encoded blob
var hexBlob = "0123456789abcdef0123456789abcdef"

// NO VIOLATION: short string
var label = "hello"

// NO VIOLATION: semver string
var version = "v1.2.3"

// NO VIOLATION: UUID
var requestID = "550e8400-e29b-41d4-a716-446655440000"

// NO VIOLATION: URL (handled by CRYPTO-PLAIN-HTTP, not key detection)
var endpoint = "https://example.com/api"

// --- CRYPTO-03 violations (plain HTTP) ---

// VIOLATION: CRYPTO-PLAIN-HTTP CRITICAL - plain HTTP URL
var paymentAPI = "http://payment.example.com/api"

// NO VIOLATION: localhost excluded
var devServer = "http://localhost:8080/api"

// NO VIOLATION: loopback excluded
var loopback = "http://127.0.0.1:9090/health"

// NO VIOLATION: HTTPS
var secureAPI = "https://secure.example.com/api"

// Ensure imports are used.
func init() {
	_ = fmt.Sprintf("%x", hashPassword("test"))
	_ = checksumData([]byte("test"))
	_ = hashUserPasswd("test")
	_ = checksumFile([]byte("test"))
}
