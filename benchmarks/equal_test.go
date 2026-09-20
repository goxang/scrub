package benchmarks

import (
	"strings"
	"testing"

	"github.com/docker/portcullis"
	"github.com/goxang/scrub"
	"github.com/goxang/scrub/packs"
)

// Three secrets both catalogues cover, so the comparison is on the same work
// rather than on who happens to ship a rule for the payload.
const (
	jwt     = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pem     = "-----BEGIN RSA PRIVATE KEY-----MIIBOgIBAAJBAKj34GkxFhD-----END RSA PRIVATE KEY-----"
	urlPass = "postgres://svc:s3cr3tpass@db:5432/switch"
)

var (
	sharedLine = `{"jwt":"` + jwt + `","key":"` + pem + `","dsn":"` + urlPass + `"}`
	sharedBig  = strings.Repeat(cleanLine+"\n", 60) + sharedLine
)

// sharedRules are the same three detections scrub has to make.
func sharedScrubber(tb testing.TB) *scrub.Scrubber {
	tb.Helper()
	var rules []scrub.Rule
	for _, r := range packs.Secrets() {
		switch r.ID {
		case "secret.jwt", "secret.private_key", "secret.url_password":
			rules = append(rules, r)
		}
	}
	s, err := scrub.New().Add(rules...).Build()
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

// TestSharedInputIsCoveredByAll fails the comparison if a library is fast only
// because it is not looking for what the others are.
func TestSharedInputIsCoveredByAll(t *testing.T) {
	s := sharedScrubber(t)
	for _, c := range []struct {
		name string
		fn   func(string) string
	}{
		{"scrub", func(in string) string { return s.Redact(in) }},
		{"portcullis", portcullis.Redact},
	} {
		out := c.fn(sharedLine)
		t.Logf("%-10s %s", c.name, out)
		for _, secret := range []string{jwt, pem, "s3cr3tpass"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s left %s… in place", c.name, secret[:12])
			}
		}
	}
}

func BenchmarkSharedScrub(b *testing.B) {
	s := sharedScrubber(b)
	eachShared(b, func(in string) string { return s.Redact(in) })
}

func BenchmarkSharedPortcullis(b *testing.B) { eachShared(b, portcullis.Redact) }

func eachShared(b *testing.B, fn func(string) string) {
	for _, in := range []struct{ name, text string }{
		{"Line", sharedLine},
		{"Big", sharedBig},
	} {
		b.Run(in.name, func(b *testing.B) {
			b.SetBytes(int64(len(in.text)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sink = fn(in.text)
			}
		})
	}
}
