package packs_test

import (
	"strings"
	"testing"

	"github.com/goxang/scrub"
	"github.com/goxang/scrub/packs"
)

func all(t *testing.T) *scrub.Scrubber {
	t.Helper()
	s, err := scrub.New(scrub.WithAllowAnchorless()).
		Add(packs.All()...).
		Add(packs.PaymentUnanchored()...).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return s
}

// Every rule gets a sample it must redact. A rule that stops firing — a
// tightened pattern, an anchor the pattern can match without — shows up here.
func TestPacksRedactTheirSamples(t *testing.T) {
	cases := []struct {
		rule   string
		in     string
		secret string
	}{
		{"payment.pan", `{"pan":"4111111111111111"}`, "4111111111111111"},
		{"payment.pan", "card_number = 5500 0000 0000 0004", "5500 0000 0000 0004"},
		{"payment.pin", "pin=1234", "1234"},
		{"payment.pin", "PIN_BLOCK: 987654", "987654"},
		{"payment.cvv", `{"cvv2": "123"}`, "123"},
		{"payment.iban", "iban=DE89370400440532013000", "DE89370400440532013000"},
		{"payment.track2", "track2=6037991199501234=29121010000012300000", "29121010000012300000"},
		{"payment.pan_bare", "sent 4111111111111111 upstream", "4111111111111111"},
		{"secret.keyed", "password=hunter2secret", "hunter2secret"},
		{"secret.keyed", `{"api_key":"abcd1234efgh5678"}`, "abcd1234efgh5678"},
		{"secret.bearer", "Authorization: Bearer abc123def456ghi", "abc123def456ghi"},
		{"secret.jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVP92K27uhbUJU1p1r_wW1gFWFOEjXk", "eyJhbGciOiJIUzI1NiJ9"},
		{"secret.private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD\n-----END RSA PRIVATE KEY-----", "MIIBOgIBAAJBAKj34GkxFhD"},
		{"secret.url_password", "dsn=postgres://svc:s3cr3tpass@db:5432/switch", "s3cr3tpass"},
		{"cloud.aws_access_key_id", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
		{"cloud.github_token", "ghp_" + strings.Repeat("a", 36), "ghp_" + strings.Repeat("a", 36)},
		{"cloud.google_api_key", "AIza" + strings.Repeat("b", 35), "AIza" + strings.Repeat("b", 35)},
		{"cloud.slack_token", "xoxb-1234567890-abcdefghij", "xoxb-1234567890-abcdefghij"},
		{"cloud.openai_key", "sk-" + strings.Repeat("c", 32), "sk-" + strings.Repeat("c", 32)},
	}

	s := all(t)
	for _, c := range cases {
		t.Run(c.rule+"/"+c.secret[:min(8, len(c.secret))], func(t *testing.T) {
			out := s.Redact(c.in)
			if strings.Contains(out, c.secret) {
				t.Fatalf("secret survived: %q", out)
			}
			if !strings.Contains(out, scrub.DefaultMarker) {
				t.Fatalf("nothing was redacted: %q", out)
			}
			if again := s.Redact(out); again != out {
				t.Errorf("not idempotent:\n once: %q\ntwice: %q", out, again)
			}

			var fired bool
			for _, m := range s.Find(c.in) {
				fired = fired || m.RuleID == c.rule
			}
			if !fired {
				t.Errorf("%s did not fire; matches: %+v", c.rule, s.Find(c.in))
			}
		})
	}
}

func TestPacksLeaveOrdinaryTextAlone(t *testing.T) {
	s := all(t)
	clean := []string{
		"amount=15000 status=OK terminal=12345678",
		`{"rrn":"123456789012","stan":"000123","response":"00"}`,
		"GET /api/v1/transactions?from=2026-01-01 HTTP/1.1",
		"card number not present",
	}
	for _, in := range clean {
		if out := s.Redact(in); out != in {
			t.Errorf("Redact(%q) = %q", in, out)
		}
	}
}

func TestPanRuleRequiresLuhn(t *testing.T) {
	s := all(t)
	// Sixteen digits that fail the checksum: a terminal serial, not a card.
	if out := s.Redact("pan=1234567812345678"); strings.Contains(out, scrub.DefaultMarker) {
		t.Errorf("Redact = %q, want the non-card left alone", out)
	}
}

func TestAnchoredPacksBuildWithoutAnchorlessRules(t *testing.T) {
	s, err := scrub.New().Add(packs.All()...).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if ids := s.Anchorless(); len(ids) != 0 {
		t.Errorf("Anchorless = %v, want none", ids)
	}
}

func TestUnanchoredPackNeedsTheOption(t *testing.T) {
	if _, err := scrub.New().Add(packs.PaymentUnanchored()...).Build(); err == nil {
		t.Fatal("Build accepted an anchorless rule without WithAllowAnchorless")
	}
}

func TestLuhn(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"4111111111111111", true},
		{"5500 0000 0000 0004", true},
		{"6037-9911-9950-1234", true},
		{"1234567812345678", false},
		{"4111", false}, // too short to be a card
		{"41111111111111x1", false},
	}
	for _, c := range cases {
		if got := packs.Luhn(c.in); got != c.want {
			t.Errorf("Luhn(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
