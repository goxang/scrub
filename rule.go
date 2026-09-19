package scrub

import "regexp"

// Rule is one pattern and the literals that gate it.
type Rule struct {
	// ID identifies the rule in a [Match] and in build errors. It must be
	// unique within a [Scrubber].
	ID string

	// Pattern is an RE2 expression, the syntax of the standard regexp
	// package.
	Pattern string

	// Anchors are literals of which every match of Pattern must contain at
	// least one. The scan looks for them, and Pattern only runs if one is
	// present: an anchor the pattern can match without is a missed secret.
	// ASCII case is folded unless [WithCaseSensitiveAnchors] is set.
	Anchors []string

	// Group names the subexpression to redact. Empty redacts the whole match.
	// Redacting only the value of a key=value pattern keeps the key readable
	// and the result idempotent.
	Group string

	// Replace overrides the marker for this rule.
	Replace string

	// Validate, when set, receives the text that would be redacted and
	// reports whether it really is a secret. It is the place for a checksum,
	// a Luhn test, or an entropy floor the pattern cannot express.
	Validate func(match string) bool
}

// Match is one redacted span, as reported by [Scrubber.Find].
type Match struct {
	RuleID string
	Start  int // byte offset of the first redacted byte
	End    int // byte offset just past the last

	rule int
}

type compiledRule struct {
	id       string
	re       *regexp.Regexp
	group    int // -1 for the whole match
	replace  string
	validate func(string) bool
}

// source hides the difference between a string and a []byte input so match
// collection is written once.
type source interface {
	findAll(re *regexp.Regexp, limit int) [][]int
	text(start, end int) string
}

type stringSource string

func (s stringSource) findAll(re *regexp.Regexp, limit int) [][]int {
	return re.FindAllStringSubmatchIndex(string(s), limit)
}

func (s stringSource) text(start, end int) string { return string(s[start:end]) }

type bytesSource []byte

func (b bytesSource) findAll(re *regexp.Regexp, limit int) [][]int {
	return re.FindAllSubmatchIndex(b, limit)
}

func (b bytesSource) text(start, end int) string { return string(b[start:end]) }
