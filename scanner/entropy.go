package scanner

import "math"

// ShannonEntropy calculates the Shannon entropy of a string in bits per character.
// Returns 0 for empty strings. Uses the standard formula: -sum(p * log2(p))
// over character frequencies.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies.
	freq := make(map[rune]int)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}

	// Calculate entropy.
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
