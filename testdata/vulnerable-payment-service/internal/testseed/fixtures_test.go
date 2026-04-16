package testseed

import "testing"

const TestCardLiteral = "4111111111111111"

func TestSeed(t *testing.T) {
	if TestCardLiteral == "" {
		t.Fatal("empty")
	}
}
