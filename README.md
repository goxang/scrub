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
| clean log line, 89 B | 53 | 1,733 | 0 | 13,324 |
| clean payload, 5.6 KB | 2,444 | 2,414 | 0 | 833,466 |
| line with 3 secrets, 80 B | 6,965 | 13 | 14 | 10,287 |
| clean line, 20 goroutines | 33 | 2,766 | 0 | — |

Clean input is 250x faster than running the rules directly, and the gap grows
with payload size. Input that does hold a secret is about 1.5x faster: the
regular expressions still have to run, and Go's `regexp` costs roughly 9ns per
byte for a pattern with no literal prefix. Redaction is for logs, so the clean
path is the one that decides your p99.

### Against the other Go libraries

`make compare` runs [benchmarks/](benchmarks), a separate module so that this
one keeps its zero dependencies. Same machine, Go 1.26, each library with its
own default catalogue ([portcullis](https://github.com/docker/portcullis) has a
fixed one, [goredact](https://github.com/lastpersonlabs/goredact) runs its
deepest profile):

| input | scrub | portcullis | goredact |
|---|---:|---:|---:|
| clean JSON line, 89 B | **56 ns** | 2,415 ns | 700 ns |
| clean JSON, 5.7 KB | **2,601 ns** | 91,992 ns | 17,577 ns |
| prose, 5.8 KB | **4,263 ns** | 11,900 ns | 16,677 ns |
| JSON line, 3 secrets | 7,761 ns | 6,125 ns | **1,075 ns** |
| 5.7 KB, 3 secrets | 334,591 ns | 266,118 ns | **19,031 ns** |

Read the last two rows with the coverage in mind, which the same module prints:
on that line scrub redacts all three secrets, portcullis redacts the card
number and leaves the keyed password, and goredact redacts none of the three —
its catalogue targets cloud and API credentials, not payment data or a password
written next to its field name. A library is not faster for walking past the
secret it was asked to find.

The clean rows are the architectural difference, and there the comparison is
like for like. portcullis prefilters as this package does, but its catalogue
includes rules that run regardless of content: on prose it reaches 480 MB/s and
on JSON, whose punctuation wakes those rules, it drops to 62 MB/s, while this
package stays above 2 GB/s because nothing in the payload matched an anchor.
Enabling `packs.PaymentUnanchored()` costs exactly the same thing, which is why
it is opt-in: with it, the 5.7 KB clean payload goes from 2,601 ns to 90,335 ns.

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
