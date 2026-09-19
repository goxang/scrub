package scrub_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/goxang/scrub"
	"github.com/goxang/scrub/packs"
)

// The three shapes that matter: a payload with no secret and no anchor, one
// with a secret, and a large clean one where the scan dominates.
const (
	cleanLine = `{"rrn":"123456789012","stan":"000123","amount":15000,"terminal":"12345678","response":"00"}`
	dirtyLine = `{"pan":"4111111111111111","pin":"1234","password":"hunter2secret","amount":15000}`
)

var bigClean = strings.Repeat(cleanLine+"\n", 64) // ~6 KB

func benchScrubber(b *testing.B) *scrub.Scrubber {
	b.Helper()
	s, err := scrub.New().Add(packs.All()...).Build()
	if err != nil {
		b.Fatal(err)
	}
	return s
}

func BenchmarkRedactClean(b *testing.B) {
	s := benchScrubber(b)
	b.SetBytes(int64(len(cleanLine)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = s.Redact(cleanLine)
	}
}

func BenchmarkRedactDirty(b *testing.B) {
	s := benchScrubber(b)
	b.SetBytes(int64(len(dirtyLine)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = s.Redact(dirtyLine)
	}
}

func BenchmarkRedactBigClean(b *testing.B) {
	s := benchScrubber(b)
	b.SetBytes(int64(len(bigClean)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = s.Redact(bigClean)
	}
}

func BenchmarkContainsClean(b *testing.B) {
	s := benchScrubber(b)
	b.SetBytes(int64(len(cleanLine)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		boolSink = s.Contains(cleanLine)
	}
}

func BenchmarkRedactBytesDirty(b *testing.B) {
	s := benchScrubber(b)
	src, buf := []byte(dirtyLine), make([]byte, 0, 256)
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = s.RedactBytes(buf[:0], src)
	}
	byteSink = buf
}

func BenchmarkParallelRedactClean(b *testing.B) {
	s := benchScrubber(b)
	b.SetBytes(int64(len(cleanLine)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sink = s.Redact(cleanLine)
		}
	})
}

// BenchmarkBaseline_* measure the alternative, not this package: the same
// rules run as plain regexps, which is what the prefilter has to beat.
var baseline = func() []*regexp.Regexp {
	var res []*regexp.Regexp
	for _, rule := range packs.All() {
		res = append(res, regexp.MustCompile(rule.Pattern))
	}
	return res
}()

func BenchmarkBaseline_RegexpClean(b *testing.B) {
	b.SetBytes(int64(len(cleanLine)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, re := range baseline {
			boolSink = re.MatchString(cleanLine)
		}
	}
}

func BenchmarkBaseline_RegexpDirty(b *testing.B) {
	b.SetBytes(int64(len(dirtyLine)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, re := range baseline {
			boolSink = re.MatchString(dirtyLine)
		}
	}
}

func BenchmarkBaseline_RegexpBigClean(b *testing.B) {
	b.SetBytes(int64(len(bigClean)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, re := range baseline {
			boolSink = re.MatchString(bigClean)
		}
	}
}

var (
	sink     string
	boolSink bool
	byteSink []byte
)

// A payload that carries a secret and is big enough for the window to matter:
// a bounded rule confirms around its anchor instead of re-scanning 5.7 KB.
var bigDirty = strings.Repeat(cleanLine+"\n", 63) + dirtyLine

func BenchmarkRedactBigDirty(b *testing.B) {
	s := benchScrubber(b)
	b.SetBytes(int64(len(bigDirty)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = s.Redact(bigDirty)
	}
}
