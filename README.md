# scrub

[![Go Reference](https://pkg.go.dev/badge/github.com/goxang/scrub.svg)](https://pkg.go.dev/github.com/goxang/scrub)
[![CI](https://github.com/goxang/scrub/actions/workflows/ci.yml/badge.svg)](https://github.com/goxang/scrub/actions/workflows/ci.yml)
[![CodeQL](https://github.com/goxang/scrub/actions/workflows/codeql.yml/badge.svg)](https://github.com/goxang/scrub/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/goxang/scrub/badge)](https://scorecard.dev/viewer/?uri=github.com/goxang/scrub)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Redact secrets out of logs and payloads with regular expressions you register
at runtime.

Each rule is an RE2 pattern plus the literal anchors it cannot match without.
Every anchor goes into one Aho-Corasick automaton, so a single pass over the
input decides which patterns could possibly match, and only those run. Text
carrying no anchor runs no regular expression and allocates nothing.

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
    MustBuild()

s.Redact(`{"pin":"1234","pan":"5022291092740569"}`)
// {"pin":"****","pan":"502229******0569"}
```

`Mask` is what keeps a value partly readable — the last four digits of a card,
the domain of an email — which a fixed `Replace` cannot do.

### Rules from elsewhere

`Rule` is a plain struct, so a catalogue maintained anywhere is just a
`[]scrub.Rule`:

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

Intel Core Ultra 7 265K, Go 1.23, all 15 rules of `packs.All()` loaded.

**The baseline column is the alternative, not this package:** the same 15
patterns compiled with the standard `regexp` package and each run over the
whole input with `ReplaceAllString` — the redaction you write when you have no
prefilter. That is what "baseline" means in every table below.

| | ns/op | MB/s | allocs/op | baseline ns/op |
|---|---:|---:|---:|---:|
| clean log line, 89 B | 58 | 1,580 | 0 | 20,855 |
| clean payload, 5.7 KB | 2,467 | 2,387 | 0 | 1,168,442 |
| line with 3 secrets, 80 B | 7,032 | 12 | 18 | 14,910 |
| 5.7 KB with 3 secrets | 48,522 | 121 | 19 | 1,185,145 |
| clean line, 20 goroutines | 33 | 2,797 | 0 | 1,413 |

Redaction is for logs, so the clean path is the one that decides your p99.

### On a corpus, not a line

A handcrafted line flatters a prefilter: it either carries an anchor or it does
not. Real logs are in between, and `BenchmarkCorpus` measures that — many lines
where almost all carry some word that is somebody's anchor (`cardCount`,
`tokenExpiry`, the `=` of every `key=value`) and almost none carry a secret.

The generated corpus follows the distribution measured over 1.2 GB of logs from
a payment switch running these rules: ~700 B per line, 98% of lines waking at
least one pattern, 1.7% carrying a secret. `SCRUB_CORPUS=/path/to/logfile`
measures your own instead.

| 5.6 MB, 8,000 lines | ns/op | MB/s | allocs/op |
|---|---:|---:|---:|
| scrub | 235,825,655 | 24 | 53,873 |
| baseline | 1,061,555,674 | 5 | 360,815 |

**4.5x, not 400x.** That is the number to plan with. The 400x on a clean line
is real but it is the best case: a line with no anchor at all. When nearly
every line wakes something, the win comes from running two or three patterns
instead of fifteen, and from confirming them near the anchor — not from
skipping the line.

### Confirming near the anchor

A rule whose pattern cannot match more than a fixed number of bytes does not
need the whole payload to confirm a hit. `Build` derives that bound from the
pattern itself — `regexp/syntax` gives the parse tree, and a walk over it
returns the longest possible match — and a rule that has one is confirmed in a
window around each anchor occurrence instead of by a pass over the input.

It is automatic and it cannot lose a secret: a pattern the walk cannot bound,
or one whose bound is larger than 8192, keeps the whole-input scan. What it
does mean is that a pattern written with an unbounded tail gives the window up:

```go
Pattern: `(?i)\bpin\b\s*[:=]\s*(?P<secret>\d{4,12})`        // unbounded: \s*
Pattern: `(?i)\bpin\b\s{0,8}[:=]\s{0,8}(?P<secret>\d{4,12})` // bounded, windowed
```

On the payment switch's own logs, bounding the catalogue this way is worth
about 2x on top of the prefilter. `Windowed()` lists the rules that qualify, so
the difference is visible rather than mysterious. Nothing else changes:
`Redact` returns the same bytes either way, which a differential fuzz target
asserts over both strategies.

### Against portcullis

`make compare` runs [benchmarks/](benchmarks), a separate module so that this
one keeps its zero dependencies.
[portcullis](https://github.com/docker/portcullis) prefilters the same way this
package does — Aho-Corasick with ASCII case folding baked into the transition
table. Same machine, Go 1.26.

On three secrets both catalogues cover (a JWT, a PEM private key and a password
in a connection string), so the numbers measure the same work:

| input | scrub | portcullis |
|---|---:|---:|
| 224 B line, 3 secrets | **11,124 ns** | 21,172 ns |
| 5.6 KB, 3 secrets | **162,553 ns** | 389,094 ns |

And on clean input, where the prefilter is the whole story:

| input | scrub | portcullis |
|---|---:|---:|
| clean JSON line, 89 B | **47 ns** | 2,276 ns |
| clean JSON, 5.7 KB | **2,421 ns** | 87,602 ns |
| prose, 5.8 KB | **3,997 ns** | 11,134 ns |

The gap on clean input is not the automaton, it is the catalogue: portcullis
ships rules that run regardless of content. Enabling `packs.PaymentUnanchored()`
here costs the same thing, which is why it is opt-in — with it the 5.7 KB clean
payload goes from 2,421 ns to 87,894 ns.

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
    Body    string   `transform:"scrub"`
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
