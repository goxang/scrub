# scrub

[![Go Reference](https://pkg.go.dev/badge/github.com/goxang/scrub.svg)](https://pkg.go.dev/github.com/goxang/scrub)
[![CI](https://github.com/goxang/scrub/actions/workflows/ci.yml/badge.svg)](https://github.com/goxang/scrub/actions/workflows/ci.yml)
[![CodeQL](https://github.com/goxang/scrub/actions/workflows/codeql.yml/badge.svg)](https://github.com/goxang/scrub/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/goxang/scrub/badge)](https://scorecard.dev/viewer/?uri=github.com/goxang/scrub)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Redact secrets out of logs and payloads, with rules registered at runtime.

Each rule carries the literal anchors its pattern cannot match without. Every
anchor goes into one Aho-Corasick automaton, so a single pass over the input
decides which rules could possibly match, and only those regular expressions
run. A line with no anchor — nearly every line a service logs — runs no regular
expression and allocates nothing.

Zero dependencies. Go 1.19+.

```bash
go get github.com/goxang/scrub
```

## Usage

```go
s, err := scrub.New().
    Add(scrub.Rule{
        ID:      "pin",
        Pattern: `(?i)\bpin\b\s*[:=]\s*(?P<secret>\d{4,12})`,
        Anchors: []string{"pin"},
        Group:   "secret",
    }).
    Build()
if err != nil {
    return err
}

s.Redact("terminal=12345678 PIN: 4321 amount=1500")
// terminal=12345678 PIN: [REDACTED] amount=1500
```

`Scrubber` is immutable after `Build` and safe for concurrent use. Beside
`Redact` there are `RedactBytes` (appends to a buffer you own), `Contains`,
`Find`, and their `*Bytes` forms.

Ready-made rules live in [`packs`](packs):

```go
s := scrub.New().Add(packs.All()...).MustBuild()
```

`packs.Payment()` covers PAN, PIN, CVV, IBAN and track 2; `packs.Secrets()`
covers keyed passwords and tokens, bearer tokens, JWTs, PEM private keys and
URL credentials; `packs.Cloud()` covers AWS, GitHub, Google, Slack and OpenAI
keys.

## Rules

| Field | Meaning |
|---|---|
| `ID` | names the rule in a `Match` and in build errors; unique |
| `Pattern` | RE2 source, the syntax of the standard `regexp` package |
| `Anchors` | literals of which every match must contain at least one |
| `Group` | named subexpression to redact; empty redacts the whole match |
| `Replace` | replacement for this rule (`"****"`, `"[MASKED]"`); empty uses the marker |
| `Mask` | builds the replacement from the matched text, when a fixed string will not do |
| `Validate` | optional check on the matched text: Luhn, a checksum, entropy |

**Anchors are the contract.** If a match can exist without any of the rule's
anchors, the prefilter never lets the pattern run and the secret survives. Pick
literals the pattern cannot match without (`password`, `AKIA`, `-----BEGIN`).
ASCII case is folded inside the automaton, so one lowercase spelling covers
every casing; `WithCaseSensitiveAnchors()` turns that off.

A rule with no anchors runs on every input. `Build` refuses one unless
`WithAllowAnchorless()` is set, and `Anchorless()` lists the ones that slipped
in, so an expensive always-on rule is visible rather than a mystery in a
profile.

The marker is the global default and every rule can override it, with a fixed
string or with a function:

```go
s := scrub.New(scrub.WithMarker("[MASKED]")).
    Add(scrub.Rule{
        ID: "pin", Anchors: []string{"pin"}, Group: "secret", Replace: "****",
        Pattern: `(?i)"pin"\s*:\s*"(?P<secret>\d{4,12})"`,
    }).
    Add(scrub.Rule{
        ID: "pan", Anchors: []string{"pan"}, Group: "secret", Mask: keepLastFour,
        Pattern: `(?i)"pan"\s*:\s*"(?P<secret>\d{12,19})"`,
    }).
    Add(scrub.Rule{
        ID: "otp", Anchors: []string{"otp"},  Group: "secret",
        Pattern: `(?i)"otp"\s*:\s*"(?P<secret>\d{4,8})"`,
    }).
    MustBuild()

s.Redact(`{"pin":"1234","pan":"5022291092740569","otp":"55555"}`)
// {"pin":"****","pan":"502229******0569","otp":"[MASKED]"}
```

`Mask` is what keeps a value partly readable — the last four digits of a card,
the domain of an email — which a fixed `Replace` cannot do.

## Rules from elsewhere

`Rule` is a plain struct, so a catalogue maintained anywhere is just a
`[]scrub.Rule` and `Add` takes it as it comes:

```go
s := scrub.New().Add(packs.All()...).Add(ourRules...).Add(vendorRules...).MustBuild()
```

Rule sets written for other tools map field for field: a gitleaks TOML rule's
`regex` is `Pattern`, its `keywords` are `Anchors`, its `secretGroup` is
`Group`. Check the anchors when you port: some catalogues treat keywords as a
hint rather than a guarantee, and here they gate the pattern.

## Behavior

- **Overlaps.** Leftmost-longest wins, ties go to the rule added first. A
  losing match is dropped, not nested.
- **Redacting twice.** It never reveals anything, and for ordinary rules it
  changes nothing: `Build` rejects a rule that matches a replacement, and
  redacting the *value* of a `key=value` pattern with `Group` leaves the second
  pass with the same text to match. It can redact *more*, because a
  replacement can create a word boundary the input did not have.
- **Errors.** `Build` fails on an unusable rule instead of dropping it: a rule
  that never fires is a leak nobody notices. Errors wrap a `*RuleError`.
- **Limits.** Up to 512 rules — the active set is a fixed bitmap on the stack,
  which is what keeps the clean path allocation-free.

## Performance

Intel Core Ultra 7 265K, Go 1.23, all 15 rules of `packs.All()` loaded. The
baseline is the same rules run as plain `regexp` calls, which is what the
prefilter has to beat.

| | ns/op | MB/s | allocs/op | baseline ns/op |
|---|---:|---:|---:|---:|
| clean log line, 89 B | 58 | 1,579 | 0 | 13,309 |
| clean payload, 5.6 KB | 2,624 | 2,249 | 0 | 835,359 |
| line with 3 secrets, 80 B | 7,341 | 11 | 18 | 10,990 |
| 5.7 KB with 3 secrets | 50,026 | 110 | 18 | — |
| clean line, 20 goroutines | 33 | 2,752 | 0 | — |

Clean input is 230x faster than running the rules directly, and the gap grows
with payload size. Redaction is for logs, so the clean path is the one that
decides your p99.

### Confirming near the anchor

A rule whose pattern cannot match more than a fixed number of bytes does not
need the whole payload to confirm a hit. `Build` derives that bound from the
pattern itself — `regexp/syntax` gives the parse tree, and a walk over it
returns the longest possible match — and a rule that has one is confirmed in a
window around each anchor occurrence instead of by a pass over the input. The
5.7 KB row above is 6.4x faster for that reason.

It is automatic and it cannot lose a secret: a pattern the walk cannot bound,
or one whose bound is larger than 8192, keeps the whole-input scan. What it
does mean is that a pattern written with an unbounded tail gives the window up:

```go
Pattern: `(?i)\bpin\b\s*[:=]\s*(?P<secret>\d{4,12})`      // unbounded: \s*
Pattern: `(?i)\bpin\b\s{0,8}[:=]\s{0,8}(?P<secret>\d{4,12})` // bounded, windowed
```

`Windowed()` lists the rules that qualify, so the difference is visible rather
than mysterious. Nothing else changes: `Redact` returns the same bytes either
way, which a differential fuzz target asserts over both strategies.

### Against the other Go libraries

`make compare` runs [benchmarks/](benchmarks), a separate module so that this
one keeps its zero dependencies. Same machine, Go 1.26.

The honest comparison is on secrets all three catalogues cover — a JWT, a PEM
private key and a password in a connection string — so every library redacts
all three and the numbers measure the same work:

| input | scrub | [portcullis](https://github.com/docker/portcullis) | [goredact](https://github.com/lastpersonlabs/goredact) |
|---|---:|---:|---:|
| 224 B line, 3 secrets | 10,735 ns | 21,556 ns | **2,393 ns** |
| 5.6 KB, 3 secrets | 168,266 ns | 417,549 ns | **19,233 ns** |

And on clean input, where the prefilter is the whole story:

| input | scrub | portcullis | goredact |
|---|---:|---:|---:|
| clean JSON line, 89 B | **56 ns** | 2,415 ns | 700 ns |
| clean JSON, 5.7 KB | **2,601 ns** | 91,992 ns | 17,577 ns |
| prose, 5.8 KB | **4,263 ns** | 11,900 ns | 16,677 ns |

Two things are worth knowing rather than being sold.

**goredact is faster once a secret is present, and the reason is structural.**
It has no regular expressions at all: a rule is a set of literal triggers plus
a hand-written Go validator, and each rule declares how far the validator may
look behind and ahead of a trigger (an AWS key ID allows 1 byte back and 18
forward). Confirming a hit costs a walk over that window, so the work scales
with the number of hits, not with the size of the payload. This package now
does the same thing where it can — see *Confirming near the anchor* — but
derives the bound from the pattern instead of asking for it, so the three rules
this table uses, whose patterns have unbounded tails, still pay for a
whole-input scan. The price of goredact's speed is the rule contract: writing a
rule means writing a byte-level validator, not a pattern.

**portcullis prefilters the same way this package does** — Aho-Corasick with
ASCII case folding baked into the transition table — and is slower on both
kinds of input: slower on clean JSON because its catalogue includes rules that
run regardless of content (on prose it reaches 480 MB/s, on JSON 62 MB/s), and
slower once a secret is present because it too runs RE2 over the whole payload
per fired rule, with more rules firing. Enabling `packs.PaymentUnanchored()`
here costs the same thing as its always-on rules do, which is why it is opt-in:
with it, the 5.7 KB clean payload goes from 2,598 ns to 93,720 ns.

The comparison module also prints what each library redacts, because a library
that walks past the secret it was asked to find is not faster.

## With goxang/transform

[transform](https://github.com/goxang/transform) applies functions to struct
fields by tag. Register a scrubber as one of them and every tagged field is
redacted wherever it sits in a struct graph:

```go
s := scrub.New().Add(packs.All()...).MustBuild()

t := transform.New()
t.RegisterString("scrub", s.Redact)

type Request struct {
    Body    string `transform:"scrub"`
    Headers []string `transform:"scrub"`
}

if err := t.Transform(&req); err != nil {
    return err
}
```

Struct tags reach the fields you know about; `Redact` reaches the free text you
do not, such as an upstream response body you log whole.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
