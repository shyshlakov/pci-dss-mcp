package panscanner

import (
	"go/ast"
	"reflect"
	"strings"
)

var bankingSiblings = map[string]bool{
	"iban":          true,
	"bic":           true,
	"swift":         true,
	"routingnumber": true,
	"sortcode":      true,
	"aba":           true,
	"bankcode":      true,
	"routingno":     true,
	"accountno":     true,
}

var pciScopeSiblings = map[string]bool{
	"cvv":                  true,
	"cvc":                  true,
	"cvv2":                 true,
	"expirymonth":          true,
	"expiryyear":           true,
	"expirationdate":       true,
	"cardholdername":       true,
	"pan":                  true,
	"cardnumber":           true,
	"primaryaccountnumber": true,
	"track1":               true,
	"track2":               true,
	"servicecode":          true,
	"pinblock":             true,
}

var tokenizationKeywords = []string{
	"token", "vault", "map", "lookup", "detok", "detokenize", "stubsource",
}

var cardTagMarkers = []string{"card_", "pan", "cvv", "cvc"}

var tagKeys = []string{"json", "gorm", "db", "bun", "sql", "form"}

func IsBankingContext(st *ast.StructType, typeName, filePath string) bool {
	if st == nil || st.Fields == nil {
		return false
	}

	lowerType := strings.ToLower(typeName)
	lowerPath := strings.ToLower(filePath)
	for _, kw := range tokenizationKeywords {
		if strings.Contains(lowerType, kw) || strings.Contains(lowerPath, kw) {
			return false
		}
	}

	var bankingCount int
	for _, field := range st.Fields.List {
		for _, ident := range field.Names {
			norm := Normalize(ident.Name)
			if pciScopeSiblings[norm] {
				return false
			}
			if bankingSiblings[norm] {
				bankingCount++
			}
		}

		if hasCardStructTag(field) {
			return false
		}
	}

	return bankingCount >= 2
}

func hasCardStructTag(field *ast.Field) bool {
	if field.Tag == nil {
		return false
	}
	raw := field.Tag.Value
	if len(raw) >= 2 && raw[0] == '`' && raw[len(raw)-1] == '`' {
		raw = raw[1 : len(raw)-1]
	}
	tag := reflect.StructTag(raw)
	for _, key := range tagKeys {
		val, ok := tag.Lookup(key)
		if !ok {
			continue
		}
		lower := strings.ToLower(val)
		for _, marker := range cardTagMarkers {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}
