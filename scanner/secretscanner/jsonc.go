package secretscanner

// StripJSONComments removes JavaScript-style comments from JSONC content and
// strips trailing commas, producing valid JSON. It uses a state machine to
// distinguish comments from content inside string literals (T-11-02).
//
// Supported comment styles:
// - // single-line comments (removed up to and including the newline)
// - /* block comments */ (removed, may span multiple lines)
//
// Trailing commas are removed: ",}" -> "}" and ",]" -> "]".
func StripJSONComments(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	out := make([]byte, 0, len(data))

	const (
		stNormal       = iota
		stInString     // inside a "..." literal
		stLineComment  // after // until newline
		stBlockComment // after /* until */
	)

	state := stNormal
	i := 0
	n := len(data)

	for i < n {
		switch state {
		case stNormal:
			if data[i] == '"' {
				state = stInString
				out = append(out, data[i])
				i++
			} else if i+1 < n && data[i] == '/' && data[i+1] == '/' {
				state = stLineComment
				i += 2 // skip //
			} else if i+1 < n && data[i] == '/' && data[i+1] == '*' {
				state = stBlockComment
				i += 2 // skip /*
			} else {
				out = append(out, data[i])
				i++
			}

		case stInString:
			if data[i] == '\\' && i+1 < n {
				// Escaped character: copy both bytes.
				out = append(out, data[i], data[i+1])
				i += 2
			} else if data[i] == '"' {
				state = stNormal
				out = append(out, data[i])
				i++
			} else {
				out = append(out, data[i])
				i++
			}

		case stLineComment:
			if data[i] == '\n' {
				state = stNormal
				out = append(out, '\n') // keep the newline for formatting
				i++
			} else {
				i++ // skip comment character
			}

		case stBlockComment:
			if i+1 < n && data[i] == '*' && data[i+1] == '/' {
				state = stNormal
				i += 2 // skip */
			} else {
				if data[i] == '\n' {
					out = append(out, '\n') // preserve newlines for line structure
				}
				i++
			}
		}
	}

	// Second pass: strip trailing commas (,<whitespace>} and,<whitespace>]).
	out = stripTrailingCommas(out)

	return out
}

// stripTrailingCommas removes commas that directly precede (with optional
// whitespace) a closing } or ]. This makes JSONC with trailing commas valid JSON.
func stripTrailingCommas(data []byte) []byte {
	result := make([]byte, 0, len(data))
	inString := false
	n := len(data)

	for i := 0; i < n; i++ {
		if !inString && data[i] == '"' {
			inString = true
			result = append(result, data[i])
			continue
		}
		if inString {
			if data[i] == '\\' && i+1 < n {
				result = append(result, data[i], data[i+1])
				i++
				continue
			}
			if data[i] == '"' {
				inString = false
			}
			result = append(result, data[i])
			continue
		}

		if data[i] == ',' {
			// Look ahead past whitespace for } or ].
			j := i + 1
			for j < n && isJSONWhitespace(data[j]) {
				j++
			}
			if j < n && (data[j] == '}' || data[j] == ']') {
				// Skip the comma; keep the whitespace and closing bracket.
				continue
			}
		}

		result = append(result, data[i])
	}

	return result
}

func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
