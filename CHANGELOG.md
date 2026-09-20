# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Repository

- `BenchmarkCorpus` measures many log lines rather than three handcrafted ones.
  Almost every line in a real log carries some word that is somebody's anchor,
  so a corpus prices the prefilter honestly: 4.5x over the same rules run as
  plain regular expressions, where a single anchorless line shows 400x. The
  generated corpus follows the distribution measured over 1.2 GB of logs from a
  payment switch running `packs.All()`; `SCRUB_CORPUS` points it at your own.
- The baseline benchmarks redact with `ReplaceAllString` rather than reporting
  `MatchString`, so they measure the same work the package does, and the two
  rows the README could not fill — a 5.7 KB payload carrying secrets, and a
  clean line on 20 goroutines — now have one.
- goredact is out of the comparison module. It has no regular expressions at
  all, so the two are not measuring the same kind of work, and keeping the row
  invited a comparison that could not be acted on. portcullis, which prefilters
  the same way this package does, stays.

### Documentation

- The README says what "baseline" means where it is first used: the same rules
  compiled with the standard `regexp` package and run over the whole input.
- The opening line says the rules are regular expressions.

## [1.1.1] - 2026-09-20

### Fixed

- A rule whose windows between them cover the whole input is confirmed by one
  pass again. Confirming near the anchor is only a saving when the windows are
  smaller than the payload; with a wide bound, or an anchor on every line, it
  was scanning the same bytes once per anchor. A 350-byte payload carrying
  eight secrets went from 151,446ns back to 112,000ns, and the large-payload
  gain is unaffected.

## [1.1.0] - 2026-09-20

### Added

- A rule whose pattern cannot match more than a fixed number of bytes is now
  confirmed in a window around each anchor occurrence instead of by a pass over
  the whole input. The bound comes from the pattern: `Build` parses it with
  `regexp/syntax` and walks the tree for the longest possible match. On an
  Intel Core Ultra 7 265K with Go 1.23 and `packs.All()` loaded, a 5.7 KB
  payload carrying three secrets went from 314,768ns to 50,026ns.
- `Scrubber.Windowed` lists the rules that qualify, the way `Anchorless` lists
  the ones that bypass the prefilter.

### Changed

- The pack rules match at most eight spaces around a field separator rather
  than any number, which is what lets them be confirmed in a window.
- A clean 89-byte line costs 58ns rather than 53ns: the scan now carries where
  each anchor was, not only which rules it woke.

### Repository

- The comparison benchmarks measure against goredact rather than
  deadpoets/secmem, and report what each library actually redacts next to how
  fast it did it.
- A second comparison runs every library over secrets all of their catalogues
  cover, so the numbers on matching input measure the same work.

## [1.0.0] - 2026-09-19

First stable release. The API is now covered by semantic versioning.

### Added

- `Rule.Mask` builds a replacement from the text being redacted, for masks
  that keep part of the value: a card number's last four digits, an email's
  domain. `Rule.Replace` still takes a fixed string, and setting both is a
  build error. The marker remains the global default, set with `WithMarker`.
- `benchmarks/`, a separate module (so this one keeps its zero dependencies)
  that measures this package against docker/portcullis and
  deadpoets/secmem on the same inputs, and prints what each one actually
  redacts. `make compare` runs it.

### Changed

- The scan skips input that cannot begin an anchor with independent loads
  instead of walking the transition table one dependent load per byte. On an
  Intel Core Ultra 7 265K with Go 1.23 and `packs.All()` loaded, a clean
  89-byte line went from 101ns to 53ns and a clean 5.6 KB payload from 6,734ns
  to 2,444ns (2,414 MB/s), both still without allocating.

### Repository

- Coverage is gated at 95%; the package is at 100%.
- Pack rules are tested against every common field shape (`k=v`, `k: v`,
  `"k" : "v"`, JSON, mixed case) rather than one sample each, and against
  secrets placed at the start, middle and end of a multi-kilobyte payload.
- `Build` refusing to overflow the uint16 state ids is covered by a test
  rather than assumed.

## [0.1.0] - 2026-09-19

### Added

- Initial release. Rules registered at runtime, each carrying the literal
  anchors its pattern cannot match without; all anchors are compiled into one
  Aho-Corasick automaton whose failure links are folded into the transition
  table, so one pass per input decides which patterns run.
- `Rule`, `Builder` and `Scrubber`, with `Redact`, `RedactBytes`, `Contains`,
  `ContainsBytes`, `Find`, `FindBytes` and `Anchorless`. A `Scrubber` is
  immutable after `Build` and safe for concurrent use.
- Options: `WithMarker`, `WithCaseSensitiveAnchors`, `WithAllowAnchorless`,
  `WithMaxMatches`.
- `Build` rejects a rule that cannot work instead of dropping it: an empty or
  duplicate ID, an empty or uncompilable pattern, an empty anchor, a group the
  pattern does not define, or a pattern that matches a replacement and would
  therefore make redaction non-idempotent. A rule with no anchors is refused
  unless `WithAllowAnchorless` is set.
- `packs`, an optional subpackage of ready-made rules for payment data,
  credentials and cloud provider keys, plus the exported `Luhn` validator.
- Input that contains no anchor runs no regular expression and allocates
  nothing; a benchmark asserts the allocation count rather than trusting it.
  On an Intel Core Ultra 7 265K with Go 1.23 and all 15 pack rules loaded, an
  89-byte clean log line takes 101ns against 13.7µs for the same rules run as
  plain regular expressions.

[Unreleased]: https://github.com/goxang/scrub/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/goxang/scrub/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/goxang/scrub/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/goxang/scrub/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/goxang/scrub/releases/tag/v0.1.0
