package scrub

import (
	"errors"
	"fmt"
)

// Errors reported by [Builder.Build]. Each is wrapped in a [*RuleError] when
// it can be traced to one rule.
var (
	ErrEmptyID        = errors.New("rule has no ID")
	ErrDuplicateID    = errors.New("rule ID is already registered")
	ErrEmptyPattern   = errors.New("rule has no pattern")
	ErrEmptyAnchor    = errors.New("rule has an empty anchor")
	ErrNoAnchors      = errors.New("rule has no anchors, so it would run on every input")
	ErrUnknownGroup   = errors.New("rule names a group its pattern does not define")
	ErrMarkerMatch    = errors.New("rule matches a replacement, so redaction would not be idempotent")
	ErrTooManyRules   = fmt.Errorf("more than %d rules", MaxRules)
	ErrTooManyStates  = fmt.Errorf("anchors need more than %d automaton states", maxStates)
	ErrEmptyMarker    = errors.New("marker is empty")
	ErrReplaceAndMask = errors.New("rule sets both Replace and Mask")
)

// RuleError identifies the rule a build failure came from.
type RuleError struct {
	ID  string
	Err error
}

func (e *RuleError) Error() string { return fmt.Sprintf("scrub: rule %q: %v", e.ID, e.Err) }

func (e *RuleError) Unwrap() error { return e.Err }

func ruleErr(id string, err error) error { return &RuleError{ID: id, Err: err} }
