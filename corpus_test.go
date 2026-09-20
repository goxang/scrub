package scrub_test

import (
	"bufio"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/goxang/scrub"
	"github.com/goxang/scrub/packs"
)

// The benchmarks above measure three handcrafted lines. This file measures a
// corpus: many lines of the shape a service actually emits, where most lines
// carry a word that is somebody's anchor and almost none carry a secret. That
// ratio, not the size of any one line, is what decides the cost in production.
//
// Set SCRUB_CORPUS to a log file to measure your own. Without it the corpus is
// generated to the distribution measured over 1.2 GB of logs from a payment
// switch running packs.All(): p50 442 B, p90 1857 B, p99 3095 B per line,
// 98.4% of lines carrying at least one anchor, 1.7% carrying a secret.

const (
	corpusLines       = 8000
	corpusSecretRatio = 60 // one line in sixty carries a secret
)

func corpus(tb testing.TB) []string {
	tb.Helper()
	if path := os.Getenv("SCRUB_CORPUS"); path != "" {
		return readCorpus(tb, path)
	}
	return generateCorpus(corpusLines)
}

func readCorpus(tb testing.TB, path string) []string {
	tb.Helper()
	file, err := os.Open(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer file.Close()

	var lines []string
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		tb.Fatal(err)
	}
	if len(lines) == 0 {
		tb.Fatalf("%s is empty", path)
	}
	return lines
}

// generateCorpus builds log lines from the fields a payment service logs.
// Most of the field names are anchors of packs.All() without being secrets —
// "cardCount", "tokenExpiry", "=" in every key=value pair — which is what
// makes a prefilter's job the real one rather than the easy one.
var corpusFields = []string{
	`"rrn":"%d"`, `"stan":"%06d"`, `"terminal":"%08d"`, `"merchant":"%d"`,
	`"amount":%d`, `"response":"00"`, `"cardCount":%d`, `"accountBalance":%d`,
	`"tokenExpiry":%d`, `"keyVersion":%d`, `"acctType":%d`, `"securityLevel":%d`,
	`"traceNo":"%06d"`, `"settlementDate":"2026-09-%02d"`, `"batch":%d`,
	`"issuer":"BANK%03d"`, `"processType":"Purchase"`, `"took":"%dms"`,
}

var corpusSecrets = []string{
	`"pin":"4321"`,
	`"pan":"4111111111111111"`,
	`"password":"hunter2secret"`,
	`"authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMiJ9.dBjftJeZ4CVPmB92K27uhbUJU1"`,
	`"apiKey":"AKIAIOSFODNN7EXAMPLE"`,
}

func generateCorpus(n int) []string {
	rng := rand.New(rand.NewSource(1))
	lines := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var b strings.Builder
		b.WriteByte('{')
		fields := corpusFieldCount(rng)
		for f := 0; f < fields; f++ {
			if f > 0 {
				b.WriteByte(',')
			}
			b.WriteString(fill(corpusFields[rng.Intn(len(corpusFields))], rng))
		}
		if i%corpusSecretRatio == 0 {
			b.WriteByte(',')
			b.WriteString(corpusSecrets[rng.Intn(len(corpusSecrets))])
		}
		b.WriteByte('}')
		lines = append(lines, b.String())
	}
	return lines
}

// corpusFieldCount draws a field count whose byte length lands on the measured
// percentiles: a short line most of the time, a dumped entity now and then.
func corpusFieldCount(rng *rand.Rand) int {
	switch r := rng.Float64(); {
	case r < 0.50:
		return 4 + rng.Intn(12)
	case r < 0.90:
		return 16 + rng.Intn(50)
	case r < 0.99:
		return 66 + rng.Intn(45)
	default:
		return 111 + rng.Intn(1100)
	}
}

func fill(format string, rng *rand.Rand) string {
	if !strings.Contains(format, "%") {
		return format
	}
	return strings.Replace(
		strings.Replace(format, "%d", strconv.Itoa(rng.Intn(1_000_000)), 1),
		"%06d", strconv.Itoa(100000+rng.Intn(899999)), 1)
}

// TestCorpusShape reports the numbers the README quotes, so a change in the
// generator or in your own corpus is visible rather than silently moving them.
func TestCorpusShape(t *testing.T) {
	lines := corpus(t)
	s := scrub.New().Add(packs.All()...).MustBuild()

	var bytes, anchored, secret int
	for _, l := range lines {
		bytes += len(l)
		if s.Redact(l) != l {
			secret++
		}
		if s.Contains(l) || wakesARule(s, l) {
			anchored++
		}
	}
	lens := make([]int, len(lines))
	for i, l := range lines {
		lens[i] = len(l)
	}
	sort.Ints(lens)
	at := func(q float64) int { return lens[int(float64(len(lens)-1)*q)] }
	t.Logf("%d lines, %.1f MB, avg %d B/line, p50 %d p90 %d p99 %d",
		len(lines), float64(bytes)/1e6, bytes/len(lines), at(.5), at(.9), at(.99))
	t.Logf("%.1f%% wake a rule, %.1f%% carry a secret",
		100*float64(anchored)/float64(len(lines)), 100*float64(secret)/float64(len(lines)))
}

// wakesARule reports whether the prefilter let any pattern run, which is the
// cost a clean line still pays.
func wakesARule(s *scrub.Scrubber, line string) bool {
	for _, r := range packs.All() {
		for _, a := range r.Anchors {
			if strings.Contains(strings.ToLower(line), strings.ToLower(a)) {
				return true
			}
		}
	}
	return false
}

func BenchmarkCorpus(b *testing.B) {
	lines := corpus(b)
	s := benchScrubber(b)
	b.SetBytes(corpusBytes(lines))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			sink = s.Redact(l)
		}
	}
}

func BenchmarkBaseline_RegexpCorpus(b *testing.B) {
	lines := corpus(b)
	b.SetBytes(corpusBytes(lines))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			for _, re := range baseline {
				sink = re.ReplaceAllString(l, "[REDACTED]")
			}
		}
	}
}

func corpusBytes(lines []string) int64 {
	var n int64
	for _, l := range lines {
		n += int64(len(l))
	}
	return n
}
