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
		compiled, err := b.compile(&b.rules[i], i, seen, &anchors, s)
		if err != nil {
			return nil, err
		}
		s.rules = append(s.rules, compiled)
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

func (b *Builder) compile(r *Rule, index int, seen map[string]struct{}, anchors *[]anchor, s *Scrubber) (compiledRule, error) {
	if r.ID == "" {
		return compiledRule{}, fmt.Errorf("scrub: rule %d: %w", index, ErrEmptyID)
	}
	if _, dup := seen[r.ID]; dup {
		return compiledRule{}, ruleErr(r.ID, ErrDuplicateID)
	}
	seen[r.ID] = struct{}{}

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

	rule := uint16(index)
	if len(r.Anchors) == 0 {
		if !b.opts.allowAnchorless {
			return compiledRule{}, ruleErr(r.ID, ErrNoAnchors)
		}
		s.always[rule>>6] |= 1 << (rule & 63)
	}
	for _, text := range r.Anchors {
		if text == "" {
			return compiledRule{}, ruleErr(r.ID, ErrEmptyAnchor)
		}
		if b.opts.foldAnchorCase {
			text = lowerASCII(text)
		}
		*anchors = append(*anchors, anchor{text: text, rule: rule})
	}
	s.all[rule>>6] |= 1 << (rule & 63)

	replace := r.Replace
	if replace == "" {
		replace = b.opts.marker
	}
	return compiledRule{id: r.ID, re: re, group: group, replace: replace, validate: r.Validate}, nil
}

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
