package httpinputscanner

// D-18 TriageHint taxonomy for HTTP-INPUT-* findings. Each rule family gets a
// first-class slot so AI triage clustering can group findings without
// reusing existing tags such as unstructured-log or error-disclosure.
const (
	triageHintLog   = "http-input-leak"
	triageHintError = "framework-input-error"
	triageHintPanic = "recovery-leak"
)

// triageHintFor maps a rule ID to its TriageHint tag.
func triageHintFor(ruleID string) string {
	switch ruleID {
	case "HTTP-INPUT-LOG":
		return triageHintLog
	case "HTTP-INPUT-ERROR":
		return triageHintError
	case "HTTP-INPUT-PANIC":
		return triageHintPanic
	}
	return ""
}
