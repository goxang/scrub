package scrub

// DefaultMarker replaces a secret when a rule sets no Replace of its own.
const DefaultMarker = "[REDACTED]"

// Option configures a [Builder]. Pass options to [New].
type Option func(*options)

type options struct {
	marker          string
	foldAnchorCase  bool
	allowAnchorless bool
	maxMatches      int
}

func defaults() options {
	return options{marker: DefaultMarker, foldAnchorCase: true}
}

// WithMarker sets the text a redacted secret is replaced with. It defaults to
// [DefaultMarker] and must not be matched by any rule.
func WithMarker(marker string) Option {
	return func(o *options) { o.marker = marker }
}

// WithCaseSensitiveAnchors matches anchors exactly. By default the automaton
// folds ASCII case, so the anchor "password" also fires on "Password" and a
// case-insensitive pattern needs only one spelling.
func WithCaseSensitiveAnchors() Option {
	return func(o *options) { o.foldAnchorCase = false }
}

// WithAllowAnchorless permits rules with no anchors. Such a rule runs its
// regular expression on every input, including text the prefilter would
// otherwise clear in one pass, so it is refused unless asked for.
func WithAllowAnchorless() Option {
	return func(o *options) { o.allowAnchorless = true }
}

// WithMaxMatches caps how many matches a single rule redacts per call. Zero,
// the default, means no cap.
func WithMaxMatches(n int) Option {
	return func(o *options) { o.maxMatches = n }
}
