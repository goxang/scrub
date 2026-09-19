package scrub

import "regexp/syntax"

// windowCap is the largest derived bound worth using. Past it the window is
// most of a log line anyway and the bookkeeping stops paying for itself.
const windowCap = 8192

// maxMatchLen is the longest match the pattern can produce, or 0 when that is
// unbounded. It is what lets a rule be confirmed near its anchor instead of
// over the whole input: a match containing an anchor cannot start more than
// this far before the anchor ends, nor end more than this far after it begins.
//
// Anything the walk does not recognise counts as unbounded, so a wrong answer
// costs speed rather than a missed secret.
func maxMatchLen(pattern string) int {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0
	}
	n := maxLen(parsed)
	if n < 0 || n > windowCap {
		return 0
	}
	return n
}

// maxLen returns the longest match of re in bytes, or -1 for unbounded.
func maxLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpNoMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0

	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			n += runeLen(r)
		}
		return n

	case syntax.OpCharClass:
		return classLen(re.Rune)

	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 4

	case syntax.OpCapture:
		return maxLen(re.Sub[0])

	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			n := maxLen(sub)
			if n < 0 {
				return -1
			}
			total += n
			if total > windowCap {
				return -1
			}
		}
		return total

	case syntax.OpAlternate:
		longest := 0
		for _, sub := range re.Sub {
			n := maxLen(sub)
			if n < 0 {
				return -1
			}
			if n > longest {
				longest = n
			}
		}
		return longest

	case syntax.OpQuest:
		return maxLen(re.Sub[0])

	case syntax.OpRepeat:
		if re.Max < 0 {
			return -1
		}
		n := maxLen(re.Sub[0])
		if n < 0 {
			return -1
		}
		if total := n * re.Max; total <= windowCap {
			return total
		}
		return -1

	default: // OpStar, OpPlus, and anything added later
		return -1
	}
}

// classLen is the longest encoding of any rune the class accepts.
func classLen(ranges []rune) int {
	longest := 0
	for i := 1; i < len(ranges); i += 2 {
		if n := runeLen(ranges[i]); n > longest {
			longest = n
		}
	}
	return longest
}

func runeLen(r rune) int {
	switch {
	case r < 0x80:
		return 1
	case r < 0x800:
		return 2
	case r < 0x10000:
		return 3
	default:
		return 4
	}
}
