package scrub

import (
	"math/bits"
	"sort"
	"strings"
)

// Scrubber redacts secrets from text. Build one with [Builder.Build]; it is
// immutable afterwards and safe for concurrent use.
type Scrubber struct {
	rules      []compiledRule
	ac         *automaton
	marker     string
	always     hitSet // rules with no anchors, which run on every input
	all        hitSet
	windowed   hitSet // rules that bound their search window
	maxMatches int
}

// edgeGuard widens a window past the derived bound, so a pattern consuming the
// bytes around its match still sees the real ones rather than the edge of a
// slice. No real match can reach this far, so one that does is an artifact of
// the window and sends the rule back over the whole input.
const edgeGuard = 32

// Redact replaces every secret in text with its rule's replacement. Text
// containing no anchor is returned unchanged, without running a regular
// expression or allocating.
func (s *Scrubber) Redact(text string) string {
	var st scanState
	active(s, text, &st)
	if st.rules == (hitSet{}) {
		return text
	}
	matches := s.collect(stringSource(text), &st)
	if len(matches) == 0 {
		return text
	}

	var out strings.Builder
	out.Grow(len(text))
	last := 0
	for _, m := range matches {
		out.WriteString(text[last:m.Start])
		out.WriteString(s.rules[m.rule].replacement(text[m.Start:m.End]))
		last = m.End
	}
	out.WriteString(text[last:])
	return out.String()
}

// RedactBytes appends the redacted form of src to dst and returns dst. Pass a
// nil dst to have it allocated, or a reused buffer to avoid that.
func (s *Scrubber) RedactBytes(dst, src []byte) []byte {
	var st scanState
	active(s, src, &st)
	if st.rules == (hitSet{}) {
		return append(dst, src...)
	}
	matches := s.collect(bytesSource(src), &st)
	if len(matches) == 0 {
		return append(dst, src...)
	}

	last := 0
	for _, m := range matches {
		rule := &s.rules[m.rule]
		dst = append(dst, src[last:m.Start]...)
		if rule.mask == nil {
			dst = append(dst, rule.replace...)
		} else {
			dst = append(dst, rule.mask(string(src[m.Start:m.End]))...)
		}
		last = m.End
	}
	return append(dst, src[last:]...)
}

// Contains reports whether text holds anything a rule would redact. It stops
// at the first secret, so it is cheaper than [Scrubber.Find] when the answer
// is all that matters.
func (s *Scrubber) Contains(text string) bool {
	var st scanState
	active(s, text, &st)
	if st.rules == (hitSet{}) {
		return false
	}
	return s.containsAny(stringSource(text), &st)
}

// ContainsBytes is [Scrubber.Contains] for a byte slice.
func (s *Scrubber) ContainsBytes(b []byte) bool {
	var st scanState
	active(s, b, &st)
	if st.rules == (hitSet{}) {
		return false
	}
	return s.containsAny(bytesSource(b), &st)
}

// Find returns the spans Redact would replace, in order and without overlaps.
func (s *Scrubber) Find(text string) []Match {
	var st scanState
	active(s, text, &st)
	if st.rules == (hitSet{}) {
		return nil
	}
	return s.collect(stringSource(text), &st)
}

// FindBytes is [Scrubber.Find] for a byte slice.
func (s *Scrubber) FindBytes(b []byte) []Match {
	var st scanState
	active(s, b, &st)
	if st.rules == (hitSet{}) {
		return nil
	}
	return s.collect(bytesSource(b), &st)
}

// Windowed lists the rules whose pattern has a bounded length, which are the
// ones confirmed around their anchors rather than over the whole input.
func (s *Scrubber) Windowed() []string {
	var ids []string
	forEachRule(s.windowed, func(idx int) {
		ids = append(ids, s.rules[idx].id)
	})
	return ids
}

// Anchorless lists the rules that run on every input because they declare no
// anchors. An unexpected name here explains a profile.
func (s *Scrubber) Anchorless() []string {
	var ids []string
	forEachRule(s.always, func(idx int) {
		ids = append(ids, s.rules[idx].id)
	})
	return ids
}

// active records the rules whose anchors are present, which is every rule the
// input could possibly match. The state is filled in place: it is large enough
// that returning it by value shows up on the clean path.
func active[T ~string | ~[]byte](s *Scrubber, in T, st *scanState) {
	st.rules = s.always
	if s.ac != nil && st.rules != s.all {
		scan(s.ac, in, st, &s.all, &s.windowed)
	}
}

func (s *Scrubber) collect(src source, st *scanState) []Match {
	var matches []Match
	s.eachMatch(src, st, s.maxMatches, func(idx, start, end int) bool {
		matches = append(matches, Match{RuleID: s.rules[idx].id, Start: start, End: end, rule: idx})
		return true
	})
	return resolve(matches)
}

func (s *Scrubber) containsAny(src source, st *scanState) bool {
	found := false
	s.eachMatch(src, st, 1, func(int, int, int) bool {
		found = true
		return false
	})
	return found
}

// eachMatch runs the active rules and reports each validated span. visit
// returning false stops the walk.
func (s *Scrubber) eachMatch(src source, st *scanState, limit int, visit func(idx, start, end int) bool) {
	stopped := false
	forEachRule(st.rules, func(idx int) {
		if stopped {
			return
		}
		// Only a rule the scan recorded positions for can be confirmed in a
		// window; an anchorless rule has none however bounded its pattern is.
		if s.windowed[idx>>6]&(1<<(idx&63)) != 0 && s.windowedMatches(src, st, idx, limit) {
			for _, span := range st.spans {
				if !visit(idx, span[0], span[1]) {
					stopped = true
					return
				}
			}
			return
		}
		s.matchesIn(src, idx, 0, src.length(), limit, func(_, _ int, start, end int) bool {
			if !visit(idx, start, end) {
				stopped = true
				return false
			}
			return true
		})
	})
}

// windowedMatches collects the rule's matches from around its anchors into
// st.spans. It reports false when a match reached the edge of a window: that
// is a match the slice boundary helped produce rather than one the whole input
// contains, so the rule is run again over everything.
func (s *Scrubber) windowedMatches(src source, st *scanState, idx, limit int) bool {
	rule := &s.rules[idx]
	n := src.length()

	// A match containing an anchor cannot start before the anchor ends minus
	// the longest possible match, nor end after the anchor starts plus the
	// same. edgeGuard widens that by enough for a pattern to read the bytes
	// around its match without seeing a synthetic edge.
	st.ranges = st.ranges[:0]
	covered := 0
	for _, hit := range st.hits {
		if int(hit.rule) != idx {
			continue
		}
		lo := maxInt(0, hit.end-rule.window-edgeGuard)
		hi := minInt(n, hit.start+rule.window+edgeGuard)
		if last := len(st.ranges) - 1; last >= 0 && lo <= st.ranges[last][1] {
			if hi > st.ranges[last][1] {
				covered += hi - st.ranges[last][1]
				st.ranges[last][1] = hi
			}
			continue
		}
		st.ranges = append(st.ranges, [2]int{lo, hi})
		covered += hi - lo
	}

	// Windows that between them cover the input are not a saving: a rule with
	// a wide bound, or with an anchor on every line, is cheaper scanned once.
	if len(st.ranges) == 0 || covered >= n {
		return false
	}

	st.spans = st.spans[:0]
	intact := true
	for _, window := range st.ranges {
		lo, hi := window[0], window[1]
		s.matchesIn(src, idx, lo, hi, limit, func(whole, wholeEnd int, start, end int) bool {
			if (whole == lo && lo > 0) || (wholeEnd == hi && hi < n) {
				intact = false
				return false
			}
			st.spans = append(st.spans, [2]int{start, end})
			return true
		})
		if !intact {
			return false
		}
	}
	return true
}

// matchesIn reports every validated match of one rule inside [lo,hi). visit
// receives the whole match span and the span that would be redacted, both in
// coordinates of the input rather than of the window.
func (s *Scrubber) matchesIn(src source, idx, lo, hi, limit int, visit func(whole, wholeEnd, start, end int) bool) {
	rule := &s.rules[idx]
	for _, loc := range src.findAllIn(rule.re, lo, hi, limit) {
		whole, wholeEnd := loc[0]+lo, loc[1]+lo
		start, end := whole, wholeEnd
		if rule.group >= 0 {
			if loc[2*rule.group] < 0 {
				// An optional group that did not participate is not a secret.
				continue
			}
			start, end = loc[2*rule.group]+lo, loc[2*rule.group+1]+lo
		}
		if end <= start {
			continue
		}
		if rule.validate != nil && !rule.validate(src.text(start, end)) {
			continue
		}
		if !visit(whole, wholeEnd, start, end) {
			return
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func forEachRule(hit hitSet, fn func(idx int)) {
	for word := 0; word < hitWords; word++ {
		for set := hit[word]; set != 0; set &= set - 1 {
			fn(word*64 + bits.TrailingZeros64(set))
		}
	}
}

// resolve drops overlaps, leftmost-longest first with ties going to the rule
// that was added first.
func resolve(matches []Match) []Match {
	if len(matches) < 2 {
		return matches
	}
	sort.Slice(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		switch {
		case a.Start != b.Start:
			return a.Start < b.Start
		case a.End != b.End:
			return a.End > b.End
		default:
			return a.rule < b.rule
		}
	})

	kept, end := matches[:0], 0
	for _, m := range matches {
		if m.Start < end {
			continue
		}
		kept = append(kept, m)
		end = m.End
	}
	return kept
}
