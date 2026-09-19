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
	maxMatches int
}

// Redact replaces every secret in text with its rule's replacement. Text
// containing no anchor is returned unchanged, without running a regular
// expression or allocating.
func (s *Scrubber) Redact(text string) string {
	hit := active(s, text)
	if hit == (hitSet{}) {
		return text
	}
	matches := s.collect(stringSource(text), hit)
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
	hit := active(s, src)
	if hit == (hitSet{}) {
		return append(dst, src...)
	}
	matches := s.collect(bytesSource(src), hit)
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
	hit := active(s, text)
	if hit == (hitSet{}) {
		return false
	}
	return s.containsAny(stringSource(text), hit)
}

// ContainsBytes is [Scrubber.Contains] for a byte slice.
func (s *Scrubber) ContainsBytes(b []byte) bool {
	hit := active(s, b)
	if hit == (hitSet{}) {
		return false
	}
	return s.containsAny(bytesSource(b), hit)
}

// Find returns the spans Redact would replace, in order and without overlaps.
func (s *Scrubber) Find(text string) []Match {
	hit := active(s, text)
	if hit == (hitSet{}) {
		return nil
	}
	return s.collect(stringSource(text), hit)
}

// FindBytes is [Scrubber.Find] for a byte slice.
func (s *Scrubber) FindBytes(b []byte) []Match {
	hit := active(s, b)
	if hit == (hitSet{}) {
		return nil
	}
	return s.collect(bytesSource(b), hit)
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

// active returns the rules whose anchors are present, which is every rule the
// input could possibly match.
func active[T ~string | ~[]byte](s *Scrubber, in T) hitSet {
	hit := s.always
	if s.ac != nil && hit != s.all {
		scan(s.ac, in, &hit, &s.all)
	}
	return hit
}

func (s *Scrubber) collect(src source, hit hitSet) []Match {
	var matches []Match
	s.eachMatch(src, hit, s.maxMatches, func(idx, start, end int) bool {
		matches = append(matches, Match{RuleID: s.rules[idx].id, Start: start, End: end, rule: idx})
		return true
	})
	return resolve(matches)
}

func (s *Scrubber) containsAny(src source, hit hitSet) bool {
	found := false
	s.eachMatch(src, hit, 1, func(int, int, int) bool {
		found = true
		return false
	})
	return found
}

// eachMatch runs the active rules and reports each validated span. visit
// returning false stops the walk.
func (s *Scrubber) eachMatch(src source, hit hitSet, limit int, visit func(idx, start, end int) bool) {
	stopped := false
	forEachRule(hit, func(idx int) {
		if stopped {
			return
		}
		rule := &s.rules[idx]
		for _, loc := range src.findAll(rule.re, limit) {
			start, end := loc[0], loc[1]
			if rule.group >= 0 {
				start, end = loc[2*rule.group], loc[2*rule.group+1]
			}
			// An optional group that did not participate reports -1, and a
			// pattern can match nothing at all; neither is a secret.
			if start < 0 || end <= start {
				continue
			}
			if rule.validate != nil && !rule.validate(src.text(start, end)) {
				continue
			}
			if !visit(idx, start, end) {
				stopped = true
				return
			}
		}
	})
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
