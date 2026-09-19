package scrub

const (
	// MaxRules is the largest number of rules one [Scrubber] can hold. The
	// set of rules a scan found is a fixed-size bitmap on the stack, which is
	// what keeps a clean input free of allocations.
	MaxRules = 512

	hitWords  = MaxRules / 64
	maxStates = 1 << 16 // state ids are uint16
	alphabet  = 256
)

type hitSet = [hitWords]uint64

// automaton is an Aho-Corasick machine over the rule anchors, with the failure
// links folded into the transition table so a scan is one lookup per byte.
type automaton struct {
	next    []uint16   // state*alphabet + byte -> state
	outs    []int32    // state -> index into outputs; 0 means no anchor ends here
	outputs [][]uint16 // rule indices, outputs[0] unused
}

type anchor struct {
	text string
	rule uint16
}

func buildAutomaton(anchors []anchor, fold bool) (*automaton, error) {
	b := builderState{next: make([]uint16, alphabet), out: make([][]uint16, 1)}
	for _, a := range anchors {
		if err := b.insert(a, fold); err != nil {
			return nil, err
		}
	}
	b.link()
	return b.freeze(), nil
}

type builderState struct {
	next []uint16
	out  [][]uint16
}

func (b *builderState) states() int { return len(b.out) }

func (b *builderState) addState() (uint16, error) {
	if b.states() >= maxStates {
		return 0, ErrTooManyStates
	}
	b.next = append(b.next, make([]uint16, alphabet)...)
	b.out = append(b.out, nil)
	return uint16(b.states() - 1), nil
}

func (b *builderState) insert(a anchor, fold bool) error {
	state := uint16(0)
	for i := 0; i < len(a.text); i++ {
		c := a.text[i]
		next := b.next[int(state)*alphabet+int(c)]
		if next == 0 { // no state is ever a successor of itself, so 0 means absent
			var err error
			if next, err = b.addState(); err != nil {
				return err
			}
			b.next[int(state)*alphabet+int(c)] = next
			if fold {
				if u := asciiUpper(c); u != c {
					b.next[int(state)*alphabet+int(u)] = next
				}
			}
		}
		state = next
	}
	b.out[state] = append(b.out[state], a.rule)
	return nil
}

// link turns the trie into a DFA: every missing edge is redirected to where
// the failure link would have sent the scan, and each state inherits the
// anchors its failure link completes.
func (b *builderState) link() {
	fail := make([]uint16, b.states())
	// Case folding gives a state two edges to the same child, so a child is
	// only queued the first time it is reached.
	queued := make([]bool, b.states())
	queue := make([]uint16, 0, b.states())
	enqueue := func(state uint16) {
		if !queued[state] {
			queued[state] = true
			queue = append(queue, state)
		}
	}
	for c := 0; c < alphabet; c++ {
		if s := b.next[c]; s != 0 {
			enqueue(s)
		}
	}
	for i := 0; i < len(queue); i++ {
		state := queue[i]
		if f := fail[state]; len(b.out[f]) > 0 {
			b.out[state] = append(b.out[state], b.out[f]...)
		}
		row, failRow := int(state)*alphabet, int(fail[state])*alphabet
		for c := 0; c < alphabet; c++ {
			next := b.next[row+c]
			if next == 0 {
				b.next[row+c] = b.next[failRow+c]
				continue
			}
			if !queued[next] {
				fail[next] = b.next[failRow+c]
				enqueue(next)
			}
		}
	}
}

func (b *builderState) freeze() *automaton {
	a := &automaton{next: b.next, outs: make([]int32, b.states()), outputs: make([][]uint16, 1, 8)}
	for state, rules := range b.out {
		if len(rules) == 0 {
			continue
		}
		a.outs[state] = int32(len(a.outputs))
		a.outputs = append(a.outputs, rules)
	}
	return a
}

// scan records every rule whose anchor occurs in the input. It stops early
// once every rule is already accounted for.
func scan[T ~string | ~[]byte](a *automaton, in T, hit, all *hitSet) {
	next, outs := a.next, a.outs
	state := 0
	for i := 0; i < len(in); i++ {
		state = int(next[state*alphabet+int(in[i])])
		if out := outs[state]; out != 0 {
			for _, rule := range a.outputs[out] {
				hit[rule>>6] |= 1 << (rule & 63)
			}
			if *hit == *all {
				return
			}
		}
	}
}

func asciiUpper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			out := []byte(s)
			for ; i < len(out); i++ {
				out[i] = asciiLower(out[i])
			}
			return string(out)
		}
	}
	return s
}
