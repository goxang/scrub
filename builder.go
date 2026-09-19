package scrub

import (
	"fmt"
	"regexp"
)

// Builder collects rules and compiles them into a [Scrubber]. It is not safe
// for concurrent use; the Scrubber it produces is.
type Builder struct {
	opts  options
	rules []Rule
}

// New starts a builder with no rules.
func New(opts ...Option) *Builder {
	b := &Builder{opts: defaults()}
	for _, opt := range opts {
		opt(&b.opts)
	}
	return b
}

// Add appends rules. Order decides which of two equally long overlapping
// matches wins.
func (b *Builder) Add(rules ...Rule) *Builder {
	b.rules = append(b.rules, rules...)
	return b
}

// Build compiles the rules. It fails on an unusable rule rather than
// silently dropping it: a rule that never fires is a leak nobody notices.
func (b *Builder) Build() (*Scrubber, error) {
	if b.opts.marker == "" {
		return nil, fmt.Errorf("scrub: %w", ErrEmptyMarker)
	}
	if len(b.rules) > MaxRules {
		return nil, fmt.Errorf("scrub: %w", ErrTooManyRules)
	}

	s := &Scrubber{
		marker:     b.opts.marker,
		rules:      make([]compiledRule, 0, len(b.rules)),
		maxMatches: -1,
	}
	if b.opts.maxMatches > 0 {
		s.maxMatches = b.opts.maxMatches
	}

	var anchors []anchor
	seen := make(map[string]struct{}, len(b.rules))
	for i := range b.rules {
		r := &b.rules[i]
		if r.ID == "" {
			return nil, fmt.Errorf("scrub: rule %d: %w", i, ErrEmptyID)
		}
		if _, duplicate := seen[r.ID]; duplicate {
			return nil, ruleErr(r.ID, ErrDuplicateID)
		}
		seen[r.ID] = struct{}{}

		compiled, err := b.compile(r)
		if err != nil {
			return nil, err
		}
		own, err := b.anchorsOf(r, uint16(i))
		if err != nil {
			return nil, err
		}

		anchors = append(anchors, own...)
		s.rules = append(s.rules, compiled)
		setRule(&s.all, i)
		if len(own) == 0 {
			setRule(&s.always, i)
		}
	}

	if err := s.rejectSelfMatch(); err != nil {
		return nil, err
	}
	if len(anchors) > 0 {
		ac, err := buildAutomaton(anchors, b.opts.foldAnchorCase)
		if err != nil {
			return nil, fmt.Errorf("scrub: %w", err)
		}
		s.ac = ac
	}
	return s, nil
}

// MustBuild is Build for package-level scrubbers, where a bad rule is a
// programming error rather than something to handle.
func (b *Builder) MustBuild() *Scrubber {
	s, err := b.Build()
	if err != nil {
		panic(err)
	}
	return s
}

func (b *Builder) compile(r *Rule) (compiledRule, error) {
	if r.Pattern == "" {
		return compiledRule{}, ruleErr(r.ID, ErrEmptyPattern)
	}
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return compiledRule{}, ruleErr(r.ID, err)
	}

	group := -1
	if r.Group != "" {
		if group = re.SubexpIndex(r.Group); group < 0 {
			return compiledRule{}, ruleErr(r.ID, fmt.Errorf("%w: %q", ErrUnknownGroup, r.Group))
		}
	}

	replace := r.Replace
	if replace == "" {
		replace = b.opts.marker
	}
	return compiledRule{id: r.ID, re: re, group: group, replace: replace, validate: r.Validate}, nil
}

func (b *Builder) anchorsOf(r *Rule, rule uint16) ([]anchor, error) {
	if len(r.Anchors) == 0 {
		if !b.opts.allowAnchorless {
			return nil, ruleErr(r.ID, ErrNoAnchors)
		}
		return nil, nil
	}

	anchors := make([]anchor, 0, len(r.Anchors))
	for _, text := range r.Anchors {
		if text == "" {
			return nil, ruleErr(r.ID, ErrEmptyAnchor)
		}
		if b.opts.foldAnchorCase {
			text = lowerASCII(text)
		}
		anchors = append(anchors, anchor{text: text, rule: rule})
	}
	return anchors, nil
}

func setRule(set *hitSet, index int) { set[index>>6] |= 1 << (index & 63) }

// rejectSelfMatch keeps redaction idempotent: if some rule sees a replacement
// as a secret, redacting twice does not give what redacting once gave.
func (s *Scrubber) rejectSelfMatch() error {
	replacements := make([]string, 0, len(s.rules)+1)
	replacements = append(replacements, s.marker)
	for _, r := range s.rules {
		replacements = append(replacements, r.replace)
	}
	for _, r := range s.rules {
		for _, replacement := range replacements {
			if r.re.MatchString(replacement) {
				return ruleErr(r.id, fmt.Errorf("%w: %q", ErrMarkerMatch, replacement))
			}
		}
	}
	return nil
}
