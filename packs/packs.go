// Package packs holds ready-made rule sets for the secrets most services leak
// into their logs. They are ordinary [scrub.Rule] values: take a pack whole,
// take part of it, or edit a rule before adding it.
//
//	s, err := scrub.New().Add(packs.Payment()...).Add(packs.Secrets()...).Build()
//
// Every rule here is anchored, except the ones from [PaymentUnanchored].
package packs

import "github.com/goxang/scrub"

// Payment returns rules for card data that appears next to a name: a PAN, PIN,
// card verification value or IBAN written as a field, plus a track 2 string,
// which is recognizable on its own.
func Payment() []scrub.Rule {
	return []scrub.Rule{
		{
			ID:       "payment.pan",
			Pattern:  `(?i)\b(?:pan|card[_-]?(?:number|no)|acct|account[_-]?number)\b["']?\s*[:=]\s*["']?(?P<secret>(?:\d[ -]?){12,18}\d)`,
			Anchors:  []string{"pan", "card", "acct", "account"},
			Group:    "secret",
			Validate: Luhn,
		},
		{
			ID:      "payment.pin",
			Pattern: `(?i)\bpin(?:[_-]?(?:block|code))?\b["']?\s*[:=]\s*["']?(?P<secret>\d{4,12})`,
			Anchors: []string{"pin"},
			Group:   "secret",
		},
		{
			ID:      "payment.cvv",
			Pattern: `(?i)\b(?:cvv2?|cvc2?|csc|card[_-]?security[_-]?code)\b["']?\s*[:=]\s*["']?(?P<secret>\d{3,4})`,
			Anchors: []string{"cvv", "cvc", "csc", "security"},
			Group:   "secret",
		},
		{
			ID:      "payment.iban",
			Pattern: `(?i)\biban\b["']?\s*[:=]\s*["']?(?P<secret>[A-Z]{2}\d{2}[A-Z0-9]{11,30})`,
			Anchors: []string{"iban"},
			Group:   "secret",
		},
		{
			// Track 2 of a magnetic stripe: the primary account number, the
			// field separator, then the expiry and discretionary data.
			ID:      "payment.track2",
			Pattern: `\b\d{13,19}=\d{7,30}\b`,
			Anchors: []string{"="},
		},
	}
}

// PaymentUnanchored returns the rules that recognize card data with no name
// beside it, such as a bare PAN in a protocol dump. They declare no anchors,
// so they run their pattern on every input and a [scrub.Builder] only accepts
// them with [scrub.WithAllowAnchorless].
func PaymentUnanchored() []scrub.Rule {
	return []scrub.Rule{
		{
			ID:       "payment.pan_bare",
			Pattern:  `\b(?:\d[ -]?){12,18}\d\b`,
			Validate: Luhn,
		},
	}
}

// Secrets returns rules for credentials that carry their own name: passwords
// and tokens written as a field, bearer tokens, JWTs, PEM private keys, and
// passwords embedded in a URL.
func Secrets() []scrub.Rule {
	return []scrub.Rule{
		{
			ID:      "secret.keyed",
			Pattern: `(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|authorization|credentials?)\b["']?\s*[:=]\s*["']?(?P<secret>[^\s"',;&]{4,256})`,
			Anchors: []string{"password", "passwd", "pwd", "secret", "token", "key", "authorization", "credential"},
			Group:   "secret",
		},
		{
			ID:      "secret.bearer",
			Pattern: `(?i)\bbearer\s+(?P<secret>[A-Za-z0-9._~+/=-]{8,})`,
			Anchors: []string{"bearer"},
			Group:   "secret",
		},
		{
			ID:      "secret.jwt",
			Pattern: `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`,
			Anchors: []string{"eyJ"},
		},
		{
			ID:      "secret.private_key",
			Pattern: `(?s)-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----`,
			Anchors: []string{"-----BEGIN"},
		},
		{
			ID:      "secret.url_password",
			Pattern: `\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:(?P<secret>[^\s/@]+)@`,
			Anchors: []string{"://"},
			Group:   "secret",
		},
	}
}

// Cloud returns rules for provider credentials that are recognizable by their
// own prefix, so they need no name beside them.
func Cloud() []scrub.Rule {
	return []scrub.Rule{
		{
			ID:      "cloud.aws_access_key_id",
			Pattern: `\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`,
			Anchors: []string{"A3T", "AKIA", "ASIA", "ABIA", "ACCA"},
		},
		{
			ID:      "cloud.github_token",
			Pattern: `\bgh[pousr]_[A-Za-z0-9]{36,255}\b`,
			Anchors: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
		},
		{
			ID:      "cloud.google_api_key",
			Pattern: `\bAIza[0-9A-Za-z_-]{35}\b`,
			Anchors: []string{"AIza"},
		},
		{
			ID:      "cloud.slack_token",
			Pattern: `\bxox[baprs]-[A-Za-z0-9-]{10,}`,
			Anchors: []string{"xox"},
		},
		{
			ID:      "cloud.openai_key",
			Pattern: `\bsk-[A-Za-z0-9_-]{16,}\b`,
			Anchors: []string{"sk-"},
		},
	}
}

// All returns every anchored pack, which is what a service that does not know
// what it logs should start from.
func All() []scrub.Rule {
	rules := Payment()
	rules = append(rules, Secrets()...)
	return append(rules, Cloud()...)
}

// Luhn reports whether the digits in s pass the Luhn checksum, ignoring spaces
// and dashes. It is the validator behind the PAN rules and is exported for
// rules of your own.
func Luhn(s string) bool {
	sum, digits, odd := 0, 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if odd {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		digits++
		odd = !odd
	}
	return digits >= 12 && sum%10 == 0
}
