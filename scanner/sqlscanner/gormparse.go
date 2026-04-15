package sqlscanner

import (
	"go/ast"
	"go/token"
	"reflect"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
)

// SensitiveTag describes one struct field whose gorm/db/sql tag references a
// sensitive cardholder column.
type SensitiveTag struct {
	ColumnName string // value after "column:" in gorm, or the full db/sql tag
	FieldName  string // Go struct field name
	FieldType  string // best-effort Go type string (e.g. "string")
	Line       int    // 1-indexed source line of the field
	TagSource  string // "gorm", "db", or "sql"
}

// GormStruct is a Go struct that has at least one sensitive DB column tag.
// HasEncryptHook is true if the file declares a method on the struct whose
// name is BeforeCreate / BeforeSave / BeforeUpdate / AfterFind and whose body
// references an Encrypt or Decrypt identifier (structural check, ).
type GormStruct struct {
	Name               string
	Line               int
	SensitiveTags      []SensitiveTag
	HasEncryptHook     bool              // kept for backward compat
	EncryptedFields    map[string]bool   // field-level encryption
	EffectiveTableName string            // resolved table name
	ColumnToField      map[string]string // lowercase gorm column → Go field name
}

// hookMethodNames are struct methods that indicate a gorm encryption hook.
var hookMethodNames = map[string]bool{
	"BeforeCreate": true,
	"BeforeSave":   true,
	"BeforeUpdate": true,
	"AfterFind":    true,
}

// ParseGormStructs walks file and returns every struct that has one or more
// sensitive DB column tags, paired with whether the struct has a valid
// BeforeCreate/BeforeSave/BeforeUpdate/AfterFind encryption hook.
func ParseGormStructs(file *ast.File, fset *token.FileSet) []GormStruct {
	if file == nil {
		return nil
	}

	// Pass 1: collect struct declarations with sensitive tags.
	type origEntry struct {
		name string
		line int
		tags []SensitiveTag
	}
	entries := map[string]*origEntry{}
	var order []string

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			structName := ts.Name.Name
			structLine := fset.Position(ts.Pos()).Line

			var sensitive []SensitiveTag
			for _, field := range st.Fields.List {
				if field.Tag == nil {
					continue
				}
				col, source := extractDBTag(field.Tag.Value)
				if col == "" || !isSensitiveColumn(col) {
					continue
				}
				fieldType := typeString(field.Type)
				// A field may declare multiple names (e.g. `A, B string`). Emit one
				// SensitiveTag per declared name to keep line numbers precise.
				if len(field.Names) == 0 {
					sensitive = append(sensitive, SensitiveTag{
						ColumnName: col,
						FieldName:  "",
						FieldType:  fieldType,
						Line:       fset.Position(field.Pos()).Line,
						TagSource:  source,
					})
					continue
				}
				for _, ident := range field.Names {
					sensitive = append(sensitive, SensitiveTag{
						ColumnName: col,
						FieldName:  ident.Name,
						FieldType:  fieldType,
						Line:       fset.Position(ident.Pos()).Line,
						TagSource:  source,
					})
				}
			}

			if len(sensitive) == 0 {
				continue
			}
			entries[structName] = &origEntry{
				name: structName,
				line: structLine,
				tags: sensitive,
			}
			order = append(order, structName)
		}
	}

	if len(entries) == 0 {
		return nil
	}

	// Pass 2: find encryption hooks.
	hooks := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name == nil {
			continue
		}
		if !hookMethodNames[fn.Name.Name] {
			continue
		}
		recvType := receiverTypeName(fn.Recv)
		if recvType == "" {
			continue
		}
		if _, tracked := entries[recvType]; !tracked {
			continue
		}
		if hookBodyHasEncryptCall(fn.Body) {
			hooks[recvType] = true
		}
	}

	out := make([]GormStruct, 0, len(order))
	for _, name := range order {
		e := entries[name]
		out = append(out, GormStruct{
			Name:           e.name,
			Line:           e.line,
			SensitiveTags:  e.tags,
			HasEncryptHook: hooks[name],
		})
	}
	return out
}

// extractDBTag parses a raw struct tag literal (including backticks) and
// returns (columnName, source) when the tag contains a sensitive DB column
// reference. Supports gorm:"column:X;...", db:"X", sql:"X". For gorm tags
// without an explicit "column:" segment, the raw gorm value is NOT returned
// (gorm's default column name comes from the field name itself, which we
// resolve separately via the field's Go identifier).
func extractDBTag(tag string) (column, source string) {
	if tag == "" {
		return "", ""
	}
	st := reflect.StructTag(strings.Trim(tag, "`"))
	if g := st.Get("gorm"); g != "" {
		for _, part := range strings.Split(g, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "column:") {
				return strings.TrimPrefix(part, "column:"), "gorm"
			}
		}
	}
	if d := st.Get("db"); d != "" {
		return d, "db"
	}
	if s := st.Get("sql"); s != "" {
		return s, "sql"
	}
	return "", ""
}

// hookBodyHasEncryptCall returns true if body contains any identifier or
// selector named Encrypt or Decrypt. This is a structural check only — we do
// not verify that the referenced function actually performs cryptographic
// work (out of scope for static analysis).
func hookBodyHasEncryptCall(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch x := n.(type) {
		case *ast.Ident:
			if x.Name == "Encrypt" || x.Name == "Decrypt" {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if x.Sel != nil && (x.Sel.Name == "Encrypt" || x.Sel.Name == "Decrypt") {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// receiverTypeName returns the struct type name from a method receiver,
// stripping any leading '*'. Returns "" if the receiver is malformed.
func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// typeString returns a best-effort string form of a Go type expression.
func typeString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + typeString(t.X)
	case *ast.SelectorExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name + "." + t.Sel.Name
		}
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + typeString(t.Elt)
		}
	}
	return ""
}

// hookEncryptedFields walks a hook method body and returns a map of receiver
// field names that are passed to Encrypt or Decrypt calls.
// It looks for assignment patterns like:
// c.FieldName = Encrypt(c.FieldName)
// c.FieldName, _ = Encrypt(c.FieldName)
// c.FieldName, err = Decrypt(c.FieldName)
func hookEncryptedFields(body *ast.BlockStmt) map[string]bool {
	fields := map[string]bool{}
	if body == nil {
		return fields
	}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		// Check RHS for Encrypt/Decrypt call.
		hasEncryptCall := false
		for _, rhs := range assign.Rhs {
			ast.Inspect(rhs, func(inner ast.Node) bool {
				switch x := inner.(type) {
				case *ast.Ident:
					if x.Name == "Encrypt" || x.Name == "Decrypt" {
						hasEncryptCall = true
						return false
					}
				case *ast.SelectorExpr:
					if x.Sel != nil && (x.Sel.Name == "Encrypt" || x.Sel.Name == "Decrypt") {
						hasEncryptCall = true
						return false
					}
				}
				return true
			})
		}
		if !hasEncryptCall {
			return true
		}
		// Extract field names from LHS: c.FieldName
		for _, lhs := range assign.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			fields[sel.Sel.Name] = true
		}
		return true
	})
	return fields
}

// cardStructHeuristics are case-insensitive substrings in struct names that
// indicate a card/payment context for table name heuristic (, rule 3).
var cardStructHeuristics = []string{"card", "token", "payment", "vault", "wallet"}

// resolveStructTableName resolves the effective table name for a Go struct.
// Priority: 1) TableName() method, 2) constant pattern, 3) name heuristic.
func resolveStructTableName(file *ast.File, structName string) string {
	// Rule 1: Find func (x *StructName) TableName() string { return "..." }
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name == nil {
			continue
		}
		if fn.Name.Name != "TableName" {
			continue
		}
		recvType := receiverTypeName(fn.Recv)
		if recvType != structName {
			continue
		}
		// Parse return statement for string literal or identifier.
		if fn.Body == nil {
			continue
		}
		for _, stmt := range fn.Body.List {
			ret, ok := stmt.(*ast.ReturnStmt)
			if !ok || len(ret.Results) == 0 {
				continue
			}
			// Direct string literal: return "cards"
			if lit, ok := ret.Results[0].(*ast.BasicLit); ok {
				return strings.Trim(lit.Value, `"`)
			}
			// Identifier referencing a constant: return CardTableName
			if ident, ok := ret.Results[0].(*ast.Ident); ok {
				// Resolve the constant in the same file.
				if val := resolveConstant(file, ident.Name); val != "" {
					return val
				}
			}
		}
	}

	// Rule 2: Find constant <StructName>TableName = "name"
	constName := structName + "TableName"
	if val := resolveConstant(file, constName); val != "" {
		return val
	}

	// Rule 3: Heuristic based on struct name.
	lower := strings.ToLower(structName)
	for _, kw := range cardStructHeuristics {
		if strings.Contains(lower, kw) {
			// Simple pluralize: add "s" to lowercased struct name.
			return panscanner.Normalize(structName) + "s"
		}
	}

	return ""
}

// resolveConstant finds a top-level constant declaration with the given name
// and returns its string value, or "" if not found.
func resolveConstant(file *ast.File, name string) string {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name {
					continue
				}
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
						return strings.Trim(lit.Value, `"`)
					}
				}
			}
		}
	}
	return ""
}

// gormFieldEntry is one db-tagged struct field collected during parsing.
type gormFieldEntry struct {
	col       string
	fieldName string
	fieldType string
	line      int
	source    string
}

// gormStructEntry groups all db-tagged fields for a struct during parsing.
type gormStructEntry struct {
	name   string
	line   int
	fields []gormFieldEntry
}

// ParseGormStructsWithContext extends ParseGormStructs with context-aware
// matching: it collects ALL db-tagged fields (not just globally sensitive ones),
// resolves table names, computes field-level encryption, and filters through
// isSensitiveColumnInContext.
func ParseGormStructsWithContext(file *ast.File, fset *token.FileSet) []GormStruct {
	if file == nil {
		return nil
	}

	entries, order := collectGormStructEntries(file, fset)
	if len(entries) == 0 {
		return nil
	}

	encryptedFieldSets := collectEncryptedFieldSets(file, entries)

	return buildGormStructs(file, entries, order, encryptedFieldSets)
}

// collectGormStructEntries walks all type declarations in file and returns
// a map of struct name -> entry with all db-tagged fields, plus the insertion
// order so callers can preserve source order in their output.
func collectGormStructEntries(file *ast.File, fset *token.FileSet) (map[string]*gormStructEntry, []string) {
	entries := map[string]*gormStructEntry{}
	var order []string

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			fields := collectDBTaggedFields(st, fset)
			if len(fields) == 0 {
				continue
			}
			structName := ts.Name.Name
			entries[structName] = &gormStructEntry{
				name:   structName,
				line:   fset.Position(ts.Pos()).Line,
				fields: fields,
			}
			order = append(order, structName)
		}
	}

	return entries, order
}

// collectDBTaggedFields extracts all db-tagged fields from a struct type,
// preserving their source positions and anonymous-field semantics.
func collectDBTaggedFields(st *ast.StructType, fset *token.FileSet) []gormFieldEntry {
	var fields []gormFieldEntry
	for _, field := range st.Fields.List {
		if field.Tag == nil {
			continue
		}
		col, source := extractDBTag(field.Tag.Value)
		if col == "" {
			continue
		}
		fieldType := typeString(field.Type)
		if len(field.Names) == 0 {
			fields = append(fields, gormFieldEntry{
				col:       col,
				fieldName: "",
				fieldType: fieldType,
				line:      fset.Position(field.Pos()).Line,
				source:    source,
			})
			continue
		}
		for _, ident := range field.Names {
			fields = append(fields, gormFieldEntry{
				col:       col,
				fieldName: ident.Name,
				fieldType: fieldType,
				line:      fset.Position(ident.Pos()).Line,
				source:    source,
			})
		}
	}
	return fields
}

// collectEncryptedFieldSets scans for BeforeCreate/BeforeSave/etc. hook
// methods on tracked structs and returns a map of receiver type name ->
// set of field names that the hook encrypts. Multiple hooks on the same
// receiver are merged.
func collectEncryptedFieldSets(file *ast.File, entries map[string]*gormStructEntry) map[string]map[string]bool {
	sets := map[string]map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name == nil {
			continue
		}
		if !hookMethodNames[fn.Name.Name] {
			continue
		}
		recvType := receiverTypeName(fn.Recv)
		if recvType == "" {
			continue
		}
		if _, tracked := entries[recvType]; !tracked {
			continue
		}
		fields := hookEncryptedFields(fn.Body)
		if existing, ok := sets[recvType]; ok {
			for k, v := range fields {
				existing[k] = v
			}
		} else {
			sets[recvType] = fields
		}
	}
	return sets
}

// buildGormStructs materializes the final GormStruct slice by resolving
// table names, computing panProtected, and filtering each entry's fields
// through context-aware matching.
func buildGormStructs(file *ast.File, entries map[string]*gormStructEntry, order []string, encryptedFieldSets map[string]map[string]bool) []GormStruct {
	out := make([]GormStruct, 0, len(order))
	for _, name := range order {
		e := entries[name]
		tableName := resolveStructTableName(file, name)
		encrypted := encryptedFieldSets[name]
		if encrypted == nil {
			encrypted = map[string]bool{}
		}

		colToField := map[string]string{}
		for _, f := range e.fields {
			colToField[strings.ToLower(f.col)] = f.fieldName
		}

		panProtected := isPANFieldProtected(e.fields, encrypted)

		sensitive := filterSensitiveTags(e.fields, tableName, panProtected)
		if len(sensitive) == 0 {
			continue
		}

		out = append(out, GormStruct{
			Name:               e.name,
			Line:               e.line,
			SensitiveTags:      sensitive,
			HasEncryptHook:     len(encrypted) > 0,
			EncryptedFields:    encrypted,
			EffectiveTableName: tableName,
			ColumnToField:      colToField,
		})
	}
	return out
}

// filterSensitiveTags keeps only fields that match context-aware sensitive
// column detection for the given table and panProtected state.
func filterSensitiveTags(fields []gormFieldEntry, tableName string, panProtected bool) []SensitiveTag {
	var sensitive []SensitiveTag
	for _, f := range fields {
		if !isSensitiveColumnInContext(tableName, f.col, panProtected) {
			continue
		}
		sensitive = append(sensitive, SensitiveTag{
			ColumnName: f.col,
			FieldName:  f.fieldName,
			FieldType:  f.fieldType,
			Line:       f.line,
			TagSource:  f.source,
		})
	}
	return sensitive
}

// isPANFieldProtected checks whether any PAN-like field in the struct has
// encryption. PAN-like = matches global panscanner keywords OR
// cardContextKeywords "number"/"account".
func isPANFieldProtected(fields []gormFieldEntry, encrypted map[string]bool) bool {
	for _, f := range fields {
		normCol := panscanner.Normalize(f.col)
		isPAN := panscanner.IsSensitiveKeyword(f.col) || normCol == "number" || normCol == "account"
		if isPAN && encrypted[f.fieldName] {
			return true
		}
	}
	// No PAN-like field found, or PAN-like field exists but not encrypted.
	// Check if any PAN-like field exists at all.
	for _, f := range fields {
		normCol := panscanner.Normalize(f.col)
		isPAN := panscanner.IsSensitiveKeyword(f.col) || normCol == "number" || normCol == "account"
		if isPAN {
			return false // PAN field exists but not encrypted
		}
	}
	// No PAN-like column at all -> panProtected=true (: no PAN to protect)
	return true
}
