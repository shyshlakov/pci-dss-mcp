package panscanner

import (
	"go/ast"
	"testing"
)

func TestIsBankingContext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		fields      []string
		tags        map[string]string
		typeName    string
		pkgPath     string
		wantBanking bool
	}{
		{
			name:        "pure_banking_IBAN_BIC_RoutingNumber",
			fields:      []string{"AccountNumber", "IBAN", "BIC", "RoutingNumber", "AccountHolder"},
			wantBanking: true,
		},
		{
			name:        "mixed_PCI_scope_CVV_blocks",
			fields:      []string{"AccountNumber", "IBAN", "CVV", "CardNumber"},
			wantBanking: false,
		},
		{
			name:        "mixed_PCI_scope_ExpiryMonth_blocks",
			fields:      []string{"AccountNumber", "IBAN", "BIC", "ExpiryMonth"},
			wantBanking: false,
		},
		{
			name:        "insufficient_banking_siblings_one_only",
			fields:      []string{"AccountNumber", "IBAN", "Name"},
			wantBanking: false,
		},
		{
			name:        "card_struct_tag_blocks",
			fields:      []string{"AccountNumber", "IBAN", "BIC"},
			tags:        map[string]string{"IBAN": "`json:\"card_iban\"`"},
			wantBanking: false,
		},
		{
			name:        "tokenization_struct_name_blocks",
			fields:      []string{"AccountNumber", "IBAN", "BIC"},
			typeName:    "TokenMapping",
			wantBanking: false,
		},
		{
			name:        "tokenization_pkg_path_blocks",
			fields:      []string{"AccountNumber", "IBAN", "BIC"},
			pkgPath:     "internal/vault/model.go",
			wantBanking: false,
		},
		{
			name:        "detokenize_pkg_path_blocks",
			fields:      []string{"AccountNumber", "IBAN", "BIC"},
			pkgPath:     "internal/detokenize/handler.go",
			wantBanking: false,
		},
		{
			name:        "SWIFT_BankCode_siblings",
			fields:      []string{"AccountNumber", "SWIFT", "BankCode", "Name"},
			wantBanking: true,
		},
		{
			name:        "SortCode_ABA_siblings",
			fields:      []string{"AccountNumber", "SortCode", "ABA"},
			wantBanking: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := buildTestStruct(tt.fields, tt.tags)
			got := IsBankingContext(st, tt.typeName, tt.pkgPath)
			if got != tt.wantBanking {
				t.Errorf("IsBankingContext() = %v, want %v", got, tt.wantBanking)
			}
		})
	}
}

func buildTestStruct(fieldNames []string, tags map[string]string) *ast.StructType {
	var fields []*ast.Field
	for _, name := range fieldNames {
		f := &ast.Field{
			Names: []*ast.Ident{{Name: name}},
			Type:  &ast.Ident{Name: "string"},
		}
		if tags != nil {
			if tag, ok := tags[name]; ok {
				f.Tag = &ast.BasicLit{Value: tag}
			}
		}
		fields = append(fields, f)
	}
	return &ast.StructType{Fields: &ast.FieldList{List: fields}}
}
