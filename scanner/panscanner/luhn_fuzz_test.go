package panscanner

import (
	"testing"
	"unicode/utf8"
)

func FuzzLuhn(f *testing.F) {
	seeds := []string{
		"",
		"0",
		"12",
		"1234567890123",
		"4111111111111111",
		"4242424242424242",
		"5500000000000004",
		"378282246310005",
		"6011111111111117",
		"3530111333300000",
		"2223000048410010",
		"4000000000006",
		"0000000000000000",
		"41111111111111111111",
		"4111 1111 1111 1111",
		"4111-1111-1111-1111",
		"4111a11111111111",
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		" 4111111111111111",
		"4111111111111111 ",
		"ｆｕｌｌｗｉｄｔｈ",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got := LuhnValid(s)
		if got {
			if n := len(s); n < 13 || n > 19 {
				t.Fatalf("LuhnValid returned true for length %d, out of 13-19 bound: %q", n, s)
			}
			for i := 0; i < len(s); i++ {
				c := s[i]
				if c < '0' || c > '9' {
					t.Fatalf("LuhnValid returned true for string with non-ASCII-digit byte 0x%02x at index %d: %q", c, i, s)
				}
			}
		}
		if !utf8.ValidString(s) && LuhnValid(s) {
			t.Fatalf("LuhnValid returned true on a string that is not valid UTF-8: %q", s)
		}
	})
}
