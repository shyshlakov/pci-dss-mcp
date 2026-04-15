package cryptoscanner

import (
	"strings"
	"unicode"
)

// valueSuffixes are words that, when following a keyword like "key" or "secret",
// indicate the variable likely holds a value (true positive). locked decision.
var valueSuffixes = map[string]bool{
	"base64":   true,
	"string":   true,
	"password": true,
	"value":    true,
	"data":     true,
	"bytes":    true,
	"pem":      true,
	"jwe":      true,
	"encoded":  true,
	"path":     true,
	"file":     true,
	"dir":      true,
}

// SplitCamelCase splits a string into words based on CamelCase, snake_case,
// and kebab-case boundaries.
//
// Examples:
//
//	"consumerKey" -> ["consumer", "Key"]
//	"HTTPSKey" -> ["HTTPS", "Key"]
//	"LogKeyRequestID" -> ["Log", "Key", "Request", "ID"]
//	"consumer_key" -> ["consumer", "key"]
//	"API_KEY" -> ["API", "KEY"]
//	"apikey" -> ["apikey"]
func SplitCamelCase(s string) []string {
	if s == "" {
		return nil
	}

	// First split on delimiters: underscore and hyphen.
	segments := splitOnDelimiters(s)

	var words []string
	for _, seg := range segments {
		words = append(words, splitCamelSegment(seg)...)
	}
	return words
}

// splitOnDelimiters splits a string on '_' and '-' characters, returning
// non-empty segments.
func splitOnDelimiters(s string) []string {
	var segments []string
	var current strings.Builder
	for _, r := range s {
		if r == '_' || r == '-' {
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		segments = append(segments, current.String())
	}
	return segments
}

// splitCamelSegment splits a single segment (no delimiters) into CamelCase words.
func splitCamelSegment(s string) []string {
	if s == "" {
		return nil
	}

	runes := []rune(s)
	var words []string
	start := 0

	for i := 1; i < len(runes); i++ {
		// Detect boundary conditions for CamelCase splitting.
		if shouldSplit(runes, i) {
			words = append(words, string(runes[start:i]))
			start = i
		}
	}

	// Add the last word.
	words = append(words, string(runes[start:]))
	return words
}

// shouldSplit determines if there should be a word boundary at position i in the rune slice.
func shouldSplit(runes []rune, i int) bool {
	curr := runes[i]
	prev := runes[i-1]

	// Case 1: lowercase -> Uppercase (e.g., "consumer|Key")
	if unicode.IsLower(prev) && unicode.IsUpper(curr) {
		return true
	}

	// Case 2: digit -> uppercase letter transition (e.g., "Base64|Key")
	if unicode.IsDigit(prev) && unicode.IsUpper(curr) {
		return true
	}

	// Case 3: Uppercase run followed by Uppercase+Lowercase (acronym boundary).
	// E.g., "HTTPS|Key" -- at position of 'K', prev is 'S' (upper), 'K' is upper, next 'e' is lower.
	// Split BEFORE the current char when: prev is upper, curr is upper, next is lower.
	if i+1 < len(runes) && unicode.IsUpper(prev) && unicode.IsUpper(curr) && unicode.IsLower(runes[i+1]) {
		return true
	}

	return false
}

// IsKeywordAtWordBoundary checks if keyword appears as a complete word in varName
// (using CamelCase/snake_case splitting) and is either the last word or followed
// by a value-suffix word.
//
// This prevents false positives like:
//
//	"LogKeyRequestID" + "key" -> false (followed by "Request", not a value-suffix)
//	"monkeyPatch" + "key" -> false ("key" is not a complete word)
//
// While preserving true positives:
//
//	"consumerKey" + "key" -> true (last word)
//	"signingKeyBase64" + "key" -> true (followed by value-suffix "Base64")
func IsKeywordAtWordBoundary(varName, keyword string) bool {
	words := SplitCamelCase(varName)

	// Check if keyword matches a complete word at a valid position.
	for i, w := range words {
		if !strings.EqualFold(w, keyword) {
			continue
		}

		// Keyword found as a complete word at position i.
		// Case 1: It's the last word.
		if i == len(words)-1 {
			return true
		}

		// Case 2: Next word is a value-suffix.
		nextWord := strings.ToLower(words[i+1])
		if valueSuffixes[nextWord] {
			return true
		}

		// Case 3: Next word starts with a digit (e.g., "Base64" already split to "Base", "64").
		// This doesn't apply -- the value-suffix check handles "base64" as a single word after split.
	}

	// Special case: compound keywords like "apikey" where the whole varName (lowered)
	// ends with the keyword and the keyword itself matches entirely.
	lower := strings.ToLower(varName)
	kw := strings.ToLower(keyword)
	return lower == kw
}
