// Package scrub removes secrets from text using rules registered at runtime.
//
// A rule is a regular expression plus the literal anchors that every match of
// it must contain. All anchors go into one Aho-Corasick automaton, so a single
// pass over the input decides which rules can possibly match, and only those
// regexes run. Text that contains no anchor runs no regular expression at all
// and allocates nothing.
//
//	s, err := scrub.New().
//		Add(scrub.Rule{
//			ID:      "pin",
//			Pattern: `(?i)\bpin\b\s*[:=]\s*(?P<secret>\d{4,12})`,
//			Anchors: []string{"pin"},
//			Group:   "secret",
//		}).
//		Build()
//	if err != nil {
//		log.Fatal(err)
//	}
//	s.Redact("pin: 1234") // "pin: [REDACTED]"
//
// # Anchors
//
// Anchors are the contract between a rule and the prefilter: if a match can
// exist without any of the rule's anchors being present, that match is missed.
// Pick literals the pattern cannot match without ("password", "AKIA",
// "-----BEGIN"), and remember that the automaton folds ASCII case by default,
// so one lowercase spelling covers every casing.
//
// A rule with no anchors runs its regular expression on every input. That is
// occasionally what you want and usually a mistake, so [Builder.Build] rejects
// such a rule unless [WithAllowAnchorless] is set.
//
// # Behavior
//
//   - Overlapping matches resolve leftmost-longest, ties going to the rule
//     added first. A losing match is dropped, not nested.
//   - Redacting twice never reveals anything. It can redact more: a
//     replacement is not the text it replaced, so it can create a word
//     boundary the input did not have. Build rejects a rule that matches a
//     replacement, which is the case where a second pass would rewrite what
//     the first one produced.
//   - A [Scrubber] is immutable after Build and safe for concurrent use. A
//     [Builder] is not.
package scrub
