package scrub

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
)

func pinRule() Rule {
	return Rule{
		ID:      "pin",
		Pattern: `(?i)\bpin\b\s*[:=]\s*(?P<secret>\d{4,12})`,
		Anchors: []string{"pin"},
		Group:   "secret",
	}
}

func build(t *testing.T, opts []Option, rules ...Rule) *Scrubber {
	t.Helper()
	s, err := New(opts...).Add(rules...).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return s
}

func TestRedact(t *testing.T) {
	s := build(t, nil, pinRule())

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"group only", "pin: 1234", "pin: [REDACTED]"},
		{"case folded anchor", "PIN=987654", "PIN=[REDACTED]"},
		{"twice", "pin=1111 and pin=2222", "pin=[REDACTED] and pin=[REDACTED]"},
		{"no anchor", "amount=1234", "amount=1234"},
		{"anchor without match", "pinned=1234", "pinned=1234"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.Redact(c.in); got != c.want {
				t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRedactLeavesCleanInputAlone(t *testing.T) {
	s := build(t, nil, pinRule())
	clean := strings.Repeat("amount=1500 status=OK terminal=12345678 ", 40)

	if got := s.Redact(clean); got != clean {
		t.Fatal("clean input was rewritten")
	}
	if n := testing.AllocsPerRun(200, func() { s.Redact(clean) }); n != 0 {
		t.Errorf("clean input allocated %v times, want 0", n)
	}
	if n := testing.AllocsPerRun(200, func() { s.Contains(clean) }); n != 0 {
		t.Errorf("Contains allocated %v times, want 0", n)
	}
}

func TestRedactIsIdempotent(t *testing.T) {
	s := build(t, nil, pinRule(), Rule{
		ID:      "password",
		Pattern: `(?i)password=(?P<secret>\S+)`,
		Anchors: []string{"password"},
		Group:   "secret",
	})

	const in = "pin=1234 password=hunter2 pin=5678"
	once := s.Redact(in)
	if twice := s.Redact(once); twice != once {
		t.Errorf("Redact is not idempotent:\n once: %q\ntwice: %q", once, twice)
	}
}

// A replacement is not the text it replaced, so it can introduce a word
// boundary the input did not have. The pass after that redacts what the
// boundary exposed; redaction only ever removes more.
func TestReplacementCanExposeAFurtherMatch(t *testing.T) {
	s := build(t, nil, pinRule())

	const in = "pin=0000pin=00000" // no word boundary before the second pin
	first := s.Redact(in)
	if first != "pin=[REDACTED]pin=00000" {
		t.Fatalf("first pass = %q", first)
	}
	second := s.Redact(first)
	if second != "pin=[REDACTED]pin=[REDACTED]" {
		t.Fatalf("second pass = %q", second)
	}
	if third := s.Redact(second); third != second {
		t.Errorf("third pass changed a settled string: %q", third)
	}
}

func TestCaseSensitiveAnchors(t *testing.T) {
	s := build(t, []Option{WithCaseSensitiveAnchors()}, pinRule())

	if got := s.Redact("pin=1234"); got != "pin=[REDACTED]" {
		t.Errorf("lowercase anchor missed: %q", got)
	}
	// The pattern is case-insensitive but the anchor is not, so the prefilter
	// never lets the pattern run. That is the documented trade.
	if got := s.Redact("PIN=1234"); got != "PIN=1234" {
		t.Errorf("uppercase should not reach the pattern: %q", got)
	}
}

func TestOverlapLeftmostLongestThenOrder(t *testing.T) {
	s := build(t, nil,
		Rule{ID: "short", Pattern: `key=\d{4}`, Anchors: []string{"key"}},
		Rule{ID: "long", Pattern: `key=\d{8}`, Anchors: []string{"key"}},
		Rule{ID: "same", Pattern: `key=\d{4}`, Anchors: []string{"key"}, Replace: "<same>"},
	)

	if got := s.Redact("key=12345678"); got != "[REDACTED]" {
		t.Errorf("longer match should win: %q", got)
	}
	// Equal spans: the rule added first wins, so the default marker is used
	// rather than the later rule's replacement.
	if got := s.Redact("key=1234"); got != "[REDACTED]" {
		t.Errorf("first rule should win a tie: %q", got)
	}
	if found := s.Find("key=1234"); len(found) != 1 || found[0].RuleID != "short" {
		t.Errorf("Find = %+v, want one match from short", found)
	}
}

func TestValidateRejectsMatch(t *testing.T) {
	s := build(t, nil, Rule{
		ID:       "even",
		Pattern:  `code=(?P<secret>\d+)`,
		Anchors:  []string{"code"},
		Group:    "secret",
		Validate: func(match string) bool { return len(match)%2 == 0 },
	})

	if got := s.Redact("code=1234 code=123"); got != "code=[REDACTED] code=123" {
		t.Errorf("Redact = %q", got)
	}
}

func TestReplacePerRule(t *testing.T) {
	s := build(t, []Option{WithMarker("<gone>")},
		pinRule(),
		Rule{ID: "otp", Pattern: `otp=(?P<secret>\d+)`, Anchors: []string{"otp"}, Group: "secret", Replace: "<otp>"},
	)

	if got := s.Redact("pin=1234 otp=999"); got != "pin=<gone> otp=<otp>" {
		t.Errorf("Redact = %q", got)
	}
}

func TestMaxMatches(t *testing.T) {
	s := build(t, []Option{WithMaxMatches(1)}, pinRule())

	if got := s.Redact("pin=1111 pin=2222"); got != "pin=[REDACTED] pin=2222" {
		t.Errorf("Redact = %q", got)
	}
}

func TestBytes(t *testing.T) {
	s := build(t, nil, pinRule())

	if got := string(s.RedactBytes(nil, []byte("pin=1234"))); got != "pin=[REDACTED]" {
		t.Errorf("RedactBytes = %q", got)
	}
	if got := string(s.RedactBytes([]byte("log: "), []byte("pin=1234"))); got != "log: pin=[REDACTED]" {
		t.Errorf("RedactBytes appends to dst: %q", got)
	}
	if got := string(s.RedactBytes(nil, []byte("amount=10"))); got != "amount=10" {
		t.Errorf("clean RedactBytes = %q", got)
	}
	if !s.ContainsBytes([]byte("pin=1234")) || s.ContainsBytes([]byte("amount=10")) {
		t.Error("ContainsBytes disagrees with RedactBytes")
	}
	if found := s.FindBytes([]byte("pin=1234")); len(found) != 1 || found[0].Start != 4 {
		t.Errorf("FindBytes = %+v", found)
	}
	if found := s.FindBytes([]byte("amount=10")); found != nil {
		t.Errorf("FindBytes on clean input = %+v, want nil", found)
	}
}

func TestBytesValidateSeesTheMatch(t *testing.T) {
	var seen string
	s := build(t, nil, Rule{
		ID:       "code",
		Pattern:  `code=(?P<secret>\d+)`,
		Anchors:  []string{"code"},
		Group:    "secret",
		Validate: func(match string) bool { seen = match; return true },
	})

	s.RedactBytes(nil, []byte("code=4321"))
	if seen != "4321" {
		t.Errorf("Validate saw %q, want the redacted span", seen)
	}
}

func TestContainsAndFind(t *testing.T) {
	s := build(t, nil, pinRule())

	if !s.Contains("pin=1234") {
		t.Error("Contains missed a secret")
	}
	if s.Contains("pinned=1234") {
		t.Error("Contains fired on an anchor with no match")
	}
	if found := s.Find("amount=1"); found != nil {
		t.Errorf("Find = %+v, want nil", found)
	}
	found := s.Find("pin=1234")
	if len(found) != 1 || found[0].RuleID != "pin" || found[0].Start != 4 || found[0].End != 8 {
		t.Errorf("Find = %+v", found)
	}
}

func TestAnchorless(t *testing.T) {
	bare := Rule{ID: "bare", Pattern: `\b\d{16}\b`}

	if _, err := New().Add(bare).Build(); !errors.Is(err, ErrNoAnchors) {
		t.Fatalf("Build error = %v, want ErrNoAnchors", err)
	}

	s := build(t, []Option{WithAllowAnchorless()}, bare, pinRule())
	if got := s.Redact("card 4111111111111111"); got != "card [REDACTED]" {
		t.Errorf("Redact = %q", got)
	}
	if ids := s.Anchorless(); len(ids) != 1 || ids[0] != "bare" {
		t.Errorf("Anchorless = %v, want [bare]", ids)
	}
	if ids := build(t, nil, pinRule()).Anchorless(); ids != nil {
		t.Errorf("Anchorless = %v, want nil", ids)
	}
}

func TestNoRulesIsANoOp(t *testing.T) {
	s := build(t, nil)

	if got := s.Redact("pin=1234"); got != "pin=1234" {
		t.Errorf("Redact = %q", got)
	}
	if s.Contains("pin=1234") || s.Find("pin=1234") != nil {
		t.Error("a scrubber with no rules found something")
	}
}

func TestUnicodeIsPreserved(t *testing.T) {
	s := build(t, nil, pinRule())
	const in = "تراکنش pin=1234 موفق بود"

	if got := s.Redact(in); got != "تراکنش pin=[REDACTED] موفق بود" {
		t.Errorf("Redact = %q", got)
	}
}

func TestBuildErrors(t *testing.T) {
	cases := []struct {
		name string
		opts []Option
		rule Rule
		want error
	}{
		{"no id", nil, Rule{Pattern: `x`, Anchors: []string{"x"}}, ErrEmptyID},
		{"no pattern", nil, Rule{ID: "a", Anchors: []string{"x"}}, ErrEmptyPattern},
		{"bad pattern", nil, Rule{ID: "a", Pattern: `(`, Anchors: []string{"x"}}, nil},
		{"empty anchor", nil, Rule{ID: "a", Pattern: `x`, Anchors: []string{""}}, ErrEmptyAnchor},
		{"unknown group", nil, Rule{ID: "a", Pattern: `x`, Anchors: []string{"x"}, Group: "nope"}, ErrUnknownGroup},
		{"matches marker", nil, Rule{ID: "a", Pattern: `[A-Z]{6,}`, Anchors: []string{"x"}}, ErrMarkerMatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.opts...).Add(c.rule).Build()
			if err == nil {
				t.Fatal("Build succeeded, want an error")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("Build error = %v, want %v", err, c.want)
			}
			var ruleError *RuleError
			if c.name != "no id" && (!errors.As(err, &ruleError) || ruleError.ID != c.rule.ID) {
				t.Errorf("error does not name the rule: %v", err)
			}
		})
	}
}

func TestBuildRejectsDuplicateID(t *testing.T) {
	_, err := New().Add(pinRule(), pinRule()).Build()
	if !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("Build error = %v, want ErrDuplicateID", err)
	}
}

func TestBuildRejectsEmptyMarker(t *testing.T) {
	if _, err := New(WithMarker("")).Add(pinRule()).Build(); !errors.Is(err, ErrEmptyMarker) {
		t.Fatalf("Build error = %v, want ErrEmptyMarker", err)
	}
}

func TestBuildRejectsARuleThatMatchesAnotherReplacement(t *testing.T) {
	_, err := New().Add(
		Rule{ID: "a", Pattern: `pin=\d+`, Anchors: []string{"pin"}, Replace: "pin=0000"},
		Rule{ID: "b", Pattern: `pin=\d+`, Anchors: []string{"pin"}},
	).Build()
	if !errors.Is(err, ErrMarkerMatch) {
		t.Fatalf("Build error = %v, want ErrMarkerMatch", err)
	}
}

func TestBuildRejectsTooManyRules(t *testing.T) {
	b := New()
	for i := 0; i <= MaxRules; i++ {
		b.Add(Rule{ID: string(rune('a'+i%26)) + strings.Repeat("x", i), Pattern: `q`, Anchors: []string{"q"}})
	}
	if _, err := b.Build(); !errors.Is(err, ErrTooManyRules) {
		t.Fatalf("Build error = %v, want ErrTooManyRules", err)
	}
}

func TestMustBuildPanicsOnABadRule(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustBuild did not panic")
		}
	}()
	New().Add(Rule{ID: "a"}).MustBuild()
}

func TestRuleErrorUnwraps(t *testing.T) {
	err := ruleErr("a", ErrNoAnchors)
	if !strings.Contains(err.Error(), `rule "a"`) || !errors.Is(err, ErrNoAnchors) {
		t.Errorf("RuleError = %v", err)
	}
}

func TestConcurrentRedact(t *testing.T) {
	s := build(t, nil, pinRule())

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if got := s.Redact("pin=1234 amount=50"); got != "pin=[REDACTED] amount=50" {
					t.Errorf("Redact = %q", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestOptionalGroupThatDidNotParticipate(t *testing.T) {
	s := build(t, nil, Rule{
		ID:      "opt",
		Pattern: `key(?:=(?P<secret>\d+))?`,
		Anchors: []string{"key"},
		Group:   "secret",
	})

	if got := s.Redact("key and key=1"); got != "key and key=[REDACTED]" {
		t.Errorf("Redact = %q", got)
	}
}

func TestAutomatonFindsOverlappingAnchors(t *testing.T) {
	rules := []Rule{
		{ID: "abc", Pattern: `abc`, Anchors: []string{"abc"}},
		{ID: "bc", Pattern: `bc`, Anchors: []string{"bc"}},
		{ID: "c", Pattern: `c!`, Anchors: []string{"c"}},
		{ID: "far", Pattern: `zzz`, Anchors: []string{"zzz"}},
	}
	s := build(t, nil, rules...)

	var st scanState
	active(s, "xxabc", &st)
	hit := st.rules
	for i, rule := range rules {
		got := hit[i>>6]&(1<<(i&63)) != 0
		if want := rule.ID != "far"; got != want {
			t.Errorf("rule %q active = %v, want %v", rule.ID, got, want)
		}
	}
}

func TestScanStopsOnceEveryRuleIsActive(t *testing.T) {
	s := build(t, nil,
		Rule{ID: "a", Pattern: `a\d`, Anchors: []string{"a"}},
		Rule{ID: "b", Pattern: `b\d`, Anchors: []string{"b"}},
	)

	var st scanState
	active(s, "ab"+strings.Repeat("q", 1000), &st)
	if st.rules != s.all {
		t.Error("both rules should be active")
	}
}

func TestLowerASCII(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"already", "already"},
		{"MiXeD", "mixed"},
		{"UTF-8 ÄÖ", "utf-8 ÄÖ"},
	} {
		if got := lowerASCII(c.in); got != c.want {
			t.Errorf("lowerASCII(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveKeepsAdjacentMatches(t *testing.T) {
	got := resolve([]Match{{Start: 4, End: 8}, {Start: 0, End: 4}})
	if len(got) != 2 || got[0].Start != 0 || got[1].Start != 4 {
		t.Errorf("resolve = %+v", got)
	}
}

func TestSubexpIndexAssumption(t *testing.T) {
	// Group resolution relies on SubexpIndex, so a change in its contract
	// would silently redact the wrong span.
	re := regexp.MustCompile(`a(?P<secret>b)`)
	if re.SubexpIndex("secret") != 1 || re.SubexpIndex("missing") != -1 {
		t.Fatal("SubexpIndex does not behave as assumed")
	}
}

func TestMaskBuildsTheReplacement(t *testing.T) {
	lastFour := func(match string) string {
		if len(match) <= 4 {
			return "****"
		}
		return strings.Repeat("*", len(match)-4) + match[len(match)-4:]
	}
	s := build(t, nil, Rule{
		ID:      "pan",
		Pattern: `(?i)pan=(?P<secret>\d{12,19})`,
		Anchors: []string{"pan"},
		Group:   "secret",
		Mask:    lastFour,
	})

	if got := s.Redact("pan=4111111111111111 ok"); got != "pan=************1111 ok" {
		t.Errorf("Redact = %q", got)
	}
	if got := string(s.RedactBytes(nil, []byte("pan=4111111111111111"))); got != "pan=************1111" {
		t.Errorf("RedactBytes = %q", got)
	}
}

func TestMaskAndReplaceTogetherAreRejected(t *testing.T) {
	_, err := New().Add(Rule{
		ID:      "both",
		Pattern: `pin=\d+`,
		Anchors: []string{"pin"},
		Replace: "****",
		Mask:    func(string) string { return "****" },
	}).Build()
	if !errors.Is(err, ErrReplaceAndMask) {
		t.Fatalf("Build error = %v, want ErrReplaceAndMask", err)
	}
}

func TestMaskedRuleStillRejectsAMarkerMatch(t *testing.T) {
	_, err := New().Add(Rule{
		ID:      "greedy",
		Pattern: `[A-Z]{6,}`,
		Anchors: []string{"x"},
		Mask:    func(string) string { return "****" },
	}).Build()
	if !errors.Is(err, ErrMarkerMatch) {
		t.Fatalf("Build error = %v, want ErrMarkerMatch", err)
	}
}

func TestMaskSeesOnlyTheGroup(t *testing.T) {
	var seen []string
	s := build(t, nil, Rule{
		ID:      "kv",
		Pattern: `key=(?P<secret>\w+)`,
		Anchors: []string{"key"},
		Group:   "secret",
		Mask: func(match string) string {
			seen = append(seen, match)
			return "<" + match[:1] + ">"
		},
	})

	if got := s.Redact("key=alpha key=beta"); got != "key=<a> key=<b>" {
		t.Errorf("Redact = %q", got)
	}
	if len(seen) != 2 || seen[0] != "alpha" || seen[1] != "beta" {
		t.Errorf("Mask saw %v", seen)
	}
}

func TestRedactBytesWithReusedBuffer(t *testing.T) {
	s := build(t, nil, pinRule())

	buf := make([]byte, 0, 64)
	for _, in := range []string{"pin=1234", "amount=1", "pin=5678 pin=9012"} {
		buf = s.RedactBytes(buf[:0], []byte(in))
		if strings.Contains(string(buf), "1234") || strings.Contains(string(buf), "5678") {
			t.Fatalf("reused buffer leaked: %q", buf)
		}
	}
	if got := string(buf); got != "pin=[REDACTED] pin=[REDACTED]" {
		t.Errorf("RedactBytes = %q", got)
	}
}

func TestScanSkipsBytesThatBeginNoAnchor(t *testing.T) {
	s := build(t, nil, pinRule())

	// The skip loop is only correct if a byte that begins an anchor still
	// enters the automaton, including at the very last position.
	for _, in := range []string{"p", "xxp", "pi", "pin", "xpin=1234", "\x00pin=1234"} {
		want := strings.Contains(in, "pin")
		var st scanState
		active(s, in, &st)
		if got := st.rules != (hitSet{}); got != want {
			t.Errorf("active(%q) = %v, want %v", in, got, want)
		}
	}
}

// State ids are uint16. Overflowing them would alias states and silently stop
// finding anchors, so Build refuses instead.
func TestBuildRejectsTooManyStates(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates the full transition table")
	}

	const letters = "abcdefghijklmnop" // 16^4 = 65536 distinct four-byte anchors
	anchors := make([]string, 0, len(letters)*len(letters)*len(letters)*len(letters))
	for a := 0; a < len(letters); a++ {
		for b := 0; b < len(letters); b++ {
			for c := 0; c < len(letters); c++ {
				for d := 0; d < len(letters); d++ {
					anchors = append(anchors, string([]byte{letters[a], letters[b], letters[c], letters[d]}))
				}
			}
		}
	}

	_, err := New(WithCaseSensitiveAnchors()).
		Add(Rule{ID: "wide", Pattern: `zzzz`, Anchors: anchors}).
		Build()
	if !errors.Is(err, ErrTooManyStates) {
		t.Fatalf("Build error = %v, want ErrTooManyStates", err)
	}
}

// windowPair builds one bounded rule twice and turns windowing off on the
// second, so the two differ only in strategy and their results must not.
func windowPair(t *testing.T) (bounded, unbounded *Scrubber) {
	t.Helper()
	rule := Rule{
		ID:      "pin",
		Pattern: `(?:^|[^A-Za-z0-9])pin\s{0,8}[:=]\s{0,8}(?P<secret>\d{4,12})`,
		Anchors: []string{"pin"},
		Group:   "secret",
	}
	bounded = build(t, nil, rule)
	if bounded.windowed == (hitSet{}) {
		t.Fatal("the rule was expected to be windowed")
	}
	unbounded = build(t, nil, rule)
	unbounded.windowed = hitSet{}
	return bounded, unbounded
}

func TestWindowedMatchesTheUnboundedScan(t *testing.T) {
	bounded, unbounded := windowPair(t)
	filler := strings.Repeat("amount=1500 status=OK ", 40)

	for _, in := range []string{
		"pin=1234",
		"xpin=1234",
		filler + "pin=1234",
		"pin=1234" + filler,
		filler + "pin=1234" + filler + "pin: 567890" + filler,
		"pin=1111 pin=2222 pin=3333",
		strings.Repeat("pin=1234 ", 50),
		"pin",
		"",
	} {
		if got, want := bounded.Redact(in), unbounded.Redact(in); got != want {
			t.Errorf("bounded and unbounded disagree on %q:\n bounded   %q\n unbounded %q", in, got, want)
		}
	}
}

// A pattern whose match length cannot be bounded keeps the whole-input scan.
func TestUnboundedPatternIsNotWindowed(t *testing.T) {
	s := build(t, nil, Rule{
		ID:      "token",
		Pattern: `token=(?P<secret>[A-Za-z0-9]+)`,
		Anchors: []string{"token"},
		Group:   "secret",
	})
	if s.windowed != (hitSet{}) {
		t.Error("a rule with an unbounded pattern was windowed")
	}
	if got, want := s.Redact("token="+strings.Repeat("a", 300)), "token=[REDACTED]"; got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}
}

func TestWindowedRulesAreReported(t *testing.T) {
	s := build(t, nil, Rule{
		ID:      "pin",
		Pattern: `pin=(?P<secret>\d{4,12})`,
		Anchors: []string{"pin"},
		Group:   "secret",
	})
	if s.windowed == (hitSet{}) {
		t.Error("a rule with a bounded pattern was not windowed")
	}
}

func TestMaxMatchLen(t *testing.T) {
	cases := []struct {
		pattern string
		want    int
	}{
		{`abc`, 3},
		{`a?bc`, 3},
		{`[0-9]{4,12}`, 12},
		{`(?:ab|cdef)`, 4},
		{`a\s{0,8}b`, 10},
		{`a+`, 0},
		{`a*`, 0},
		{`[0-9]{4,}`, 0},
		{`(?s).*`, 0},
		{`\bpin\b`, 3},
		{`(`, 0},   // unparsable, which Build rejects anyway
		{`a.c`, 6}, // any char is up to four bytes
		{`(?s)a(.)c`, 6},
		{`(?:ab|c+)`, 0}, // one unbounded branch is enough
		{`x(?:ab)?y`, 4},
		{`[é-ü]{2}`, 4}, // two-byte runes
		{`[\x{1F600}-\x{1F64F}]`, 4},
		{`(?:abc){0,3}`, 9},
		{`a{0,9000}`, 0},          // past the cap
		{`a{0,5000}b{0,5000}`, 0}, // each part fits, the concatenation does not
		{`^$`, 0},
	}
	for _, c := range cases {
		if got := maxMatchLen(c.pattern); got != c.want {
			t.Errorf("maxMatchLen(%q) = %d, want %d", c.pattern, got, c.want)
		}
	}
}

// Two anchors close together share one window; far apart they get their own.
func TestWindowsMergeAndSplit(t *testing.T) {
	bounded, unbounded := windowPair(t)
	for _, in := range []string{
		"pin=1111 pin=2222",
		"pin=1111" + strings.Repeat(" ", 500) + "pin=2222",
	} {
		if got, want := bounded.Redact(in), unbounded.Redact(in); got != want {
			t.Errorf("%q:\n bounded   %q\n unbounded %q", in, got, want)
		}
	}
}

func TestWindowedBytesPath(t *testing.T) {
	bounded, unbounded := windowPair(t)
	in := []byte(strings.Repeat("amount=1 ", 30) + "pin=1234")

	if got, want := string(bounded.RedactBytes(nil, in)), string(unbounded.RedactBytes(nil, in)); got != want {
		t.Errorf("RedactBytes = %q, want %q", got, want)
	}
}

func TestWindowedReportsTheRules(t *testing.T) {
	s := build(t, nil, Rule{
		ID:      "pin",
		Pattern: `pin=(?P<secret>\d{4,12})`,
		Anchors: []string{"pin"},
		Group:   "secret",
	}, Rule{
		ID:      "token",
		Pattern: `token=(?P<secret>\w+)`,
		Anchors: []string{"token"},
		Group:   "secret",
	})

	if got := s.Windowed(); len(got) != 1 || got[0] != "pin" {
		t.Errorf("Windowed = %v, want [pin]", got)
	}
}

// The window is sized so that a real match cannot reach its edge. If it ever
// did — a bound smaller than the pattern can match — the rule has to go back
// over the whole input rather than trust what it saw. Shrinking the window by
// hand is the only way to reach that branch, which is the point of it.
func TestWindowEdgeSendsTheRuleBackOverTheWholeInput(t *testing.T) {
	rule := Rule{
		ID:      "pin",
		Pattern: `pin=(?P<secret>\d{29})`,
		Anchors: []string{"pin"},
		Group:   "secret",
	}
	const (
		digits = "12345678901234567890123456789"
		// A cramped window ends exactly where this match does.
		cramp = 1
	)
	filler := strings.Repeat("-", 200)

	for _, in := range []string{
		filler + "pin=" + digits,
		filler + "pin=" + digits + filler + "pin=" + digits,
	} {
		s := build(t, nil, rule)
		want := s.Redact(in)

		cramped := build(t, nil, rule)
		cramped.rules[0].window = cramp
		if got := cramped.Redact(in); got != want {
			t.Errorf("cramped window changed the result:\n got  %q\n want %q", got, want)
		}
		if !strings.Contains(want, "[REDACTED]") {
			t.Fatal("the fixture stopped containing a secret")
		}
	}
}

// An optional group that did not participate is not a secret, in a window as
// much as over the whole input.
func TestWindowedOptionalGroup(t *testing.T) {
	s := build(t, nil, Rule{
		ID:      "opt",
		Pattern: `key(?:=(?P<secret>\d{1,4}))?`,
		Anchors: []string{"key"},
		Group:   "secret",
	})

	in := strings.Repeat(".", 100) + "key and key=12"
	if got, want := s.Redact(in), strings.Repeat(".", 100)+"key and key=[REDACTED]"; got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}
}

// A group that matched nothing is not a secret, in a window as much as over
// the whole input.
func TestWindowedEmptyGroup(t *testing.T) {
	s := build(t, nil, Rule{
		ID:      "key",
		Pattern: `key(?P<secret>\d{0,4})`,
		Anchors: []string{"key"},
		Group:   "secret",
	})
	if s.windowed == (hitSet{}) {
		t.Fatal("the rule was expected to be windowed")
	}

	in := strings.Repeat(".", 100) + "key and key12"
	if got, want := s.Redact(in), strings.Repeat(".", 100)+"key and key[REDACTED]"; got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}
}
