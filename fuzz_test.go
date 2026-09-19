package scrub

import (
	"strings"
	"testing"
)

func fuzzScrubber(t *testing.T) *Scrubber {
	t.Helper()
	return build(t, []Option{WithAllowAnchorless()},
		Rule{ID: "pin", Pattern: `(?i)\bpin\b\s*[:=]\s*(?P<secret>\d{4,12})`, Anchors: []string{"pin"}, Group: "secret"},
		Rule{ID: "password", Pattern: `(?i)password\s*[:=]\s*(?P<secret>[^\s",]+)`, Anchors: []string{"password"}, Group: "secret"},
		Rule{ID: "token", Pattern: `\bghp_[A-Za-z0-9]{8,}\b`, Anchors: []string{"ghp_"}},
		Rule{ID: "digits", Pattern: `\b\d{16}\b`},
	)
}

func FuzzRedact(f *testing.F) {
	for _, seed := range []string{
		"", "pin", "pin=1234", "PIN : 000000 password=x1", "ghp_abcdefgh",
		"4111111111111111", "پین=1234", strings.Repeat("pin=1234 ", 20),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in string) {
		s := fuzzScrubber(t)

		matches := s.Find(in)
		end := 0
		for _, m := range matches {
			if m.Start < end || m.End <= m.Start || m.End > len(in) {
				t.Fatalf("Find returned %+v out of order or out of bounds for %q", matches, in)
			}
			end = m.End
		}

		out := s.Redact(in)
		if (len(matches) == 0) != (out == in) {
			t.Fatalf("Redact(%q) = %q, which disagrees with Find %+v", in, out, matches)
		}
		// Replacing a secret can create a word boundary the input did not
		// have, so a later pass can redact more than the first. What has to
		// hold is that the text settles and that nothing is left behind. The
		// bound keeps a large fuzz input from turning this into a quadratic
		// walk. A settled text can still match a rule — a redacted value is
		// what the rule matches on the next pass — so what is checked is that
		// the text stops changing.
		if len(in) <= 512 {
			settled := out
			for i := 0; i <= len(in); i++ {
				next := s.Redact(settled)
				if next == settled {
					break
				}
				settled = next
			}
			if s.Redact(settled) != settled {
				t.Fatalf("Redact did not settle on %q, reached %q", in, settled)
			}
		}
		if bytes := string(s.RedactBytes(nil, []byte(in))); bytes != out {
			t.Fatalf("RedactBytes(%q) = %q, want %q", in, bytes, out)
		}
		if s.Contains(in) != (len(matches) > 0) {
			t.Fatalf("Contains(%q) disagrees with Find", in)
		}
	})
}

// FuzzWindowed is the guarantee behind the derived window: confirming a rule
// near its anchors may change how long redaction takes, never what it
// produces.
func FuzzWindowed(f *testing.F) {
	for _, seed := range []string{
		"", "pin", "pin=1234", "xpin=1234 pin: 567890",
		strings.Repeat("a", 200) + "pin=1234",
		"pin=1234" + strings.Repeat("b", 200),
		"pin=1111 pin=2222 pin=3333",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in string) {
		bounded, unbounded := windowPair(t)
		if got, want := bounded.Redact(in), unbounded.Redact(in); got != want {
			t.Fatalf("bounded %q, unbounded %q, for input %q", got, want, in)
		}
		if got, want := bounded.Contains(in), unbounded.Contains(in); got != want {
			t.Fatalf("Contains disagree on %q", in)
		}
		if got, want := len(bounded.Find(in)), len(unbounded.Find(in)); got != want {
			t.Fatalf("Find returned %d and %d matches for %q", got, want, in)
		}
	})
}
