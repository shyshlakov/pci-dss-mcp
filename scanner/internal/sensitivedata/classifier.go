package sensitivedata

import "regexp"

type Kind int

const (
	KindUnknown Kind = iota
	KindPAN
	KindSAD
)

var (
	sadMatcher = regexp.MustCompile(`(?i)\b(cvv2?|cvc2?|cid|card[_ ]?verification|security[_ ]?code|track[12]?([_ ]?data)?|magstripe|pin([_ ]?block)?|encrypted[_ ]?pin)\b`)
	panMatcher = regexp.MustCompile(`(?i)\b(pan|card[_ ]?number|primary[_ ]?account[_ ]?number|account[_ ]?number|cardNo|ccNo|credit[_ ]?card)\b`)
)

func Classify(name string) Kind {
	if name == "" {
		return KindUnknown
	}
	if sadMatcher.MatchString(name) {
		return KindSAD
	}
	if panMatcher.MatchString(name) {
		return KindPAN
	}
	return KindUnknown
}
