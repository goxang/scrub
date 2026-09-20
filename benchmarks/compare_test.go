// Package benchmarks compares scrub with portcullis, the other Go library
// that prefilters before running its patterns. Each runs its own default
// catalogue, which is how it would be used; TestRedactsTheSecrets prints what
// each one actually removes, because a library that is fast on an input it
// does not cover is not faster.
package benchmarks

import (
	"strings"
	"testing"

	"github.com/docker/portcullis"
	"github.com/goxang/scrub"
	"github.com/goxang/scrub/packs"
)

const (
	cleanLine = `{"rrn":"123456789012","stan":"000123","amount":15000,"terminal":"12345678","response":"00"}`
	dirtyLine = `{"pan":"4111111111111111","pin":"1234","password":"hunter2secret","amount":15000}`
)

var (
	bigClean = strings.Repeat(cleanLine+"\n", 64) // 5.7 KB
	bigDirty = strings.Repeat(cleanLine+"\n", 63) + dirtyLine
	// Prose of the same size, without the punctuation a JSON payload carries.
	// It separates the cost of scanning from the cost of a rule that some byte
	// in the payload woke up.
	bigProse = strings.Repeat("the quick brown fox jumps over the lazy dog and keeps running ", 93)
)

var inputs = []struct {
	name string
	text string
}{
	{"CleanLine", cleanLine},
	{"CleanBig", bigClean},
	{"DirtyLine", dirtyLine},
	{"DirtyBig", bigDirty},
	{"ProseBig", bigProse},
}

// scrubUnanchored adds the bare-PAN rule, which has no anchors and therefore
// runs on every input. It is here to price that choice.
func BenchmarkScrubUnanchored(b *testing.B) {
	s := scrub.New(scrub.WithAllowAnchorless()).
		Add(packs.All()...).
		Add(packs.PaymentUnanchored()...).
		MustBuild()
	each(b, func(in string) string { return s.Redact(in) })
}

func BenchmarkScrub(b *testing.B) {
	s := scrub.New().Add(packs.All()...).MustBuild()
	each(b, func(in string) string { return s.Redact(in) })
}

func BenchmarkPortcullis(b *testing.B) { each(b, portcullis.Redact) }

func each(b *testing.B, fn func(string) string) {
	for _, in := range inputs {
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

var sink string

// TestRedactsTheSecrets keeps the comparison honest: a library that is fast
// because it finds nothing is not faster, it is broken for this input.
func TestRedactsTheSecrets(t *testing.T) {
	s := scrub.New().Add(packs.All()...).MustBuild()
	for _, c := range []struct {
		name string
		fn   func(string) string
	}{
		{"scrub", func(in string) string { return s.Redact(in) }},
		{"portcullis", portcullis.Redact},
	} {
		out := c.fn(dirtyLine)
		t.Logf("%-10s %s", c.name, out)
		for _, secret := range []string{"4111111111111111", "hunter2secret"} {
			if strings.Contains(out, secret) {
				t.Logf("  %s leaves %q in place", c.name, secret)
			}
		}
	}
}
