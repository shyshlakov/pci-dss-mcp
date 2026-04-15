package sqlscanner

import (
	"regexp"
	"strings"
)

// Column is a single column declaration extracted from a CREATE TABLE or
// ALTER TABLE ADD COLUMN statement. Name is preserved as written (minus quoting),
// SQLType is lowercased with any parenthesized size/precision preserved
// (e.g. "varchar(4)", "numeric(10,2)"). Line is the 1-indexed source line where
// the column name appears.
type Column struct {
	Name      string
	SQLType   string
	Line      int
	TableName string // table that owns this column
}

// createTableHeadRE matches the head of a CREATE TABLE statement, up to and
// including the first '(' that opens the column-list body. The body is parsed
// forward by a paren-counter (not regex) so nested parens in types such as
// varchar(4) / numeric(10,2) do not confuse extraction. The match must not
// cross a leading comment — stripLineComments zeroes them out first.
var createTableHeadRE = regexp.MustCompile(`(?is)\bCREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+[` + "`" + `"]?([\w.]+)[` + "`" + `"]?\s*\(`)

// alterAddColumnRE matches `ALTER TABLE <t> ADD [COLUMN] <col> <type>[(...)]`.
// The type group greedily captures letters + digits + optional parenthesized
// size list so numeric(10,2) / varchar(255) round-trip correctly.
var alterAddColumnRE = regexp.MustCompile(
	`(?is)\bALTER\s+TABLE\s+[` + "`" + `"]?([\w.]+)[` + "`" + `"]?\s+ADD\s+(?:COLUMN\s+)?` +
		`[` + "`" + `"]?(\w+)[` + "`" + `"]?\s+` +
		`([a-zA-Z][a-zA-Z0-9_ ]*(?:\([0-9, ]+\))?)`,
)

// plaintextStringTypeRE identifies SQL column types that store strings in
// plaintext (not acceptable for PAN/SAD per PCI DSS 3.5.1).
var plaintextStringTypeRE = regexp.MustCompile(
	`(?i)^(text|varchar(\([0-9]+\))?|character varying(\([0-9]+\))?|char(\([0-9]+\))?|citext|string)$`,
)

// reservedConstraintKeywords are leading tokens that indicate a table-level
// constraint clause (not a column definition). parseColumnList skips them.
var reservedConstraintKeywords = map[string]bool{
	"primary":    true,
	"foreign":    true,
	"unique":     true,
	"check":      true,
	"constraint": true,
	"index":      true,
	"key":        true,
	"exclude":    true,
}

// stripLineComments replaces every `--...` comment with spaces while
// preserving the overall byte length and line count. This keeps source offsets
// (and therefore line numbers derived from `strings.Count(src[:i], "\n")`)
// accurate in downstream passes.
func stripLineComments(src string) string {
	if !strings.Contains(src, "--") {
		return src
	}
	buf := []byte(src)
	i := 0
	for i < len(buf) {
		if i+1 < len(buf) && buf[i] == '-' && buf[i+1] == '-' {
			// Blank out until end-of-line (or end-of-file).
			for i < len(buf) && buf[i] != '\n' {
				buf[i] = ' '
				i++
			}
			continue
		}
		i++
	}
	return string(buf)
}

// ParseSQLFile extracts every column declaration visible in CREATE TABLE or
// ALTER TABLE ADD COLUMN statements. Line comments (`--...`) are stripped
// before parsing. DROP TABLE, INSERT, UPDATE, SELECT statements are ignored.
func ParseSQLFile(src string) []Column {
	clean := stripLineComments(src)

	var cols []Column

	// Pass 1: CREATE TABLE bodies via paren-counting forward scan.
	for _, m := range createTableHeadRE.FindAllStringSubmatchIndex(clean, -1) {
		// m[0.1] = full match, m[2.3] = table name capture group.
		// m[1] is the byte offset *after* the opening '('.
		bodyStart := m[1]
		bodyEnd := findMatchingClose(clean, bodyStart)
		if bodyEnd < 0 {
			continue
		}
		tableName := clean[m[2]:m[3]]
		body := clean[bodyStart:bodyEnd]
		startLine := 1 + strings.Count(clean[:bodyStart], "\n")
		cols = append(cols, parseColumnList(body, startLine, tableName)...)
	}

	// Pass 2: ALTER TABLE ADD COLUMN.
	for _, m := range alterAddColumnRE.FindAllStringSubmatchIndex(clean, -1) {
		line := 1 + strings.Count(clean[:m[0]], "\n")
		// m[2.3] = table name, m[4.5] = column name, m[6.7] = type.
		tableName := clean[m[2]:m[3]]
		name := clean[m[4]:m[5]]
		typ := strings.ToLower(strings.TrimSpace(clean[m[6]:m[7]]))
		cols = append(cols, Column{Name: name, SQLType: typ, Line: line, TableName: tableName})
	}

	return cols
}

// findMatchingClose scans from start (just past an opening '(') and returns
// the index of the matching ')' or -1 if none is found. Character classes in
// string literals are not considered — migration files rarely embed
// parentheses inside string literals in CREATE TABLE bodies.
func findMatchingClose(s string, start int) int {
	depth := 1
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// parseColumnList tokenizes a CREATE TABLE body into column definitions.
// The body is split on top-level commas (commas inside parentheses, such as
// numeric(10,2), are ignored). startLine is the 1-indexed source line of the
// first byte of body in the original file.
func parseColumnList(body string, startLine int, tableName string) []Column {
	var cols []Column
	depth := 0
	start := 0
	flush := func(end int) {
		segment := body[start:end]
		// Line offset of the first non-whitespace byte of the segment.
		leading := 0
		for leading < len(segment) && (segment[leading] == ' ' || segment[leading] == '\t' || segment[leading] == '\n' || segment[leading] == '\r') {
			leading++
		}
		lineOffset := strings.Count(body[:start+leading], "\n")
		if col, ok := parseColumnSegment(segment, startLine+lineOffset); ok {
			col.TableName = tableName
			cols = append(cols, col)
		}
	}
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				flush(i)
				start = i + 1
			}
		}
	}
	if start < len(body) {
		flush(len(body))
	}
	return cols
}

// parseColumnSegment parses one segment (between top-level commas) into a
// Column. Returns ok=false if the segment is a table-level constraint clause
// (PRIMARY KEY, FOREIGN KEY, CHECK, UNIQUE, CONSTRAINT, INDEX, KEY).
func parseColumnSegment(segment string, line int) (Column, bool) {
	trimmed := strings.TrimSpace(segment)
	if trimmed == "" {
		return Column{}, false
	}
	// First token = column name (stripped of quotes/backticks).
	// Second token = type (plus optional parenthesized size).
	// We use a single forward walk so we can preserve parenthesized size.
	name, rest := nextToken(trimmed)
	if name == "" {
		return Column{}, false
	}
	if reservedConstraintKeywords[strings.ToLower(name)] {
		return Column{}, false
	}
	name = strings.Trim(name, "`\"")
	typ, _ := nextTypeToken(strings.TrimSpace(rest))
	typ = strings.ToLower(strings.TrimSpace(typ))
	return Column{Name: name, SQLType: typ, Line: line}, true
}

// nextToken returns the first whitespace-delimited token and the remainder.
func nextToken(s string) (string, string) {
	i := 0
	for i < len(s) && !isSpace(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

// nextTypeToken returns the type token including an optional parenthesized
// size/precision list (e.g. "varchar(255)", "numeric(10,2)"). It consumes the
// leading identifier plus the first balanced parenthesized group that
// immediately follows it. Multi-word types like "character varying(128)" are
// also handled: if the next whitespace-separated token is a pure identifier
// and the remainder begins with '(' or another identifier, we append it.
func nextTypeToken(s string) (string, string) {
	if s == "" {
		return "", s
	}
	// Consume identifier.
	i := 0
	for i < len(s) && isIdentByte(s[i]) {
		i++
	}
	tok := s[:i]
	rest := s[i:]
	// Optional second identifier word (e.g. "character varying").
	j := 0
	for j < len(rest) && isSpace(rest[j]) {
		j++
	}
	if j > 0 && j < len(rest) && isIdentByte(rest[j]) {
		k := j
		for k < len(rest) && isIdentByte(rest[k]) {
			k++
		}
		second := rest[j:k]
		lowerFirst := strings.ToLower(tok)
		lowerSecond := strings.ToLower(second)
		if lowerFirst == "character" && (lowerSecond == "varying" || lowerSecond == "large") {
			tok = tok + " " + second
			rest = rest[k:]
		}
	}
	// Optional parenthesized size.
	k := 0
	for k < len(rest) && isSpace(rest[k]) {
		k++
	}
	if k < len(rest) && rest[k] == '(' {
		depth := 1
		p := k + 1
		for p < len(rest) && depth > 0 {
			switch rest[p] {
			case '(':
				depth++
			case ')':
				depth--
			}
			p++
		}
		if depth == 0 {
			tok = tok + rest[k:p]
			rest = rest[p:]
		}
	}
	return tok, rest
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func isIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

// IsPlaintextStringType reports whether t is a SQL column type that stores
// strings in plaintext (text, varchar[(n)], char[(n)], character varying[(n)],
// citext, string). bytea and other non-string types return false.
func IsPlaintextStringType(t string) bool {
	return plaintextStringTypeRE.MatchString(strings.TrimSpace(strings.ToLower(t)))
}
