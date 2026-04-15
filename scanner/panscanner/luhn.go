package panscanner

import (
	"strconv"
	"strings"
)

// LuhnValid returns true if number passes the Luhn checksum algorithm.
// Returns false for empty strings, non-digit characters, or lengths outside 13-19.
// The 13-19 bounds also cap work on pathological long strings.
func LuhnValid(number string) bool {
	n := len(number)
	if n < 13 || n > 19 {
		return false
	}

	var sum int
	double := false
	// Iterate right-to-left.
	for i := n - 1; i >= 0; i-- {
		d := number[i]
		if d < '0' || d > '9' {
			return false
		}
		digit := int(d - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

// iinRule describes an IIN brand rule: prefix(es), either a single fixed
// range or a list of exact strings, plus the allowed lengths.
type iinRule struct {
	digitLen      int // how many leading digits to compare against rangeLo/rangeHi (0 = use fixedPrefixes)
	rangeLo       int
	rangeHi       int
	fixedPrefixes []string
	lengths       []int
}

// iinRules is the canonical brand table consulted by MatchesIINPrefix. It
// replaces the per-brand if-chain so adding a new brand is a one-line change.
var iinRules = []iinRule{
	// Visa: starts with '4', len 13/16/19.
	{digitLen: 1, rangeLo: 4, rangeHi: 4, lengths: []int{13, 16, 19}},
	// Mastercard: prefix 51-55 len 16.
	{digitLen: 2, rangeLo: 51, rangeHi: 55, lengths: []int{16}},
	// Mastercard 2-series: prefix 2221-2720 len 16.
	{digitLen: 4, rangeLo: 2221, rangeHi: 2720, lengths: []int{16}},
	// Amex: prefix 34 or 37, len 15.
	{fixedPrefixes: []string{"34", "37"}, lengths: []int{15}},
	// Discover: prefix 6011, len 16-19.
	{fixedPrefixes: []string{"6011"}, lengths: []int{16, 17, 18, 19}},
	// Discover: prefix 644-649, len 16-19.
	{digitLen: 3, rangeLo: 644, rangeHi: 649, lengths: []int{16, 17, 18, 19}},
	// Discover: prefix 65, len 16-19.
	{fixedPrefixes: []string{"65"}, lengths: []int{16, 17, 18, 19}},
	// JCB: prefix 3528-3589, len 16-19.
	{digitLen: 4, rangeLo: 3528, rangeHi: 3589, lengths: []int{16, 17, 18, 19}},
}

// MatchesIINPrefix returns true if number matches any brand rule in iinRules.
func MatchesIINPrefix(number string) bool {
	n := len(number)
	if n < 13 || n > 19 {
		return false
	}
	for _, rule := range iinRules {
		if matchesIINRule(number, n, rule) {
			return true
		}
	}
	return false
}

// matchesIINRule reports whether number of length n satisfies a single rule.
func matchesIINRule(number string, n int, rule iinRule) bool {
	if !containsInt(rule.lengths, n) {
		return false
	}
	if len(rule.fixedPrefixes) > 0 {
		for _, p := range rule.fixedPrefixes {
			if strings.HasPrefix(number, p) {
				return true
			}
		}
		return false
	}
	if rule.digitLen == 0 || len(number) < rule.digitLen {
		return false
	}
	prefix, err := strconv.Atoi(number[:rule.digitLen])
	if err != nil {
		return false
	}
	return prefix >= rule.rangeLo && prefix <= rule.rangeHi
}

// containsInt returns true if v is present in xs.
func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// IsLikelyPAN returns true if number is both Luhn-valid and matches a known
// IIN prefix. This dual check significantly reduces false positives.
func IsLikelyPAN(number string) bool {
	return LuhnValid(number) && MatchesIINPrefix(number)
}

// ExtractDigits strips all non-digit characters from s. Used by.env scanner
// and string literal scanner to extract potential PANs from formatted values
// like "4111-1111-1111-1111".
func ExtractDigits(s string) string {
	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			buf = append(buf, s[i])
		}
	}
	return string(buf)
}
