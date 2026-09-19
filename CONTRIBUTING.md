# Contributing

Thanks for taking the time. This is a small, dependency-free package whose job
is to not leak secrets; the bar for new surface area is high and the bar for
correctness is higher.

## Before you start

Open an issue first for anything beyond a bug fix, a new rule, or a doc
correction. The [issue templates](.github/ISSUE_TEMPLATE) ask the questions
that usually decide whether a change belongs here.

Changes that are likely to be accepted:

- A secret the packs miss, with a sample that fails today. Use fabricated
  values; never put a real credential in an issue, a test, or a commit.
- A rule whose anchors do not hold, so the prefilter skips a real match.
- A hot-path improvement with before/after benchmarks.
- Documentation that clarifies behavior someone got wrong in practice.

Changes that are likely to be declined:

- Anything that makes the clean path allocate. Text with no anchor is the
  common case and it stays free.
- Scanning features that belong in a scanner: git history, file walking,
  verification against a provider's API, reporting formats.
- New dependencies. The package has none and intends to keep it that way. A
  faster automaton is welcome as code, not as a `require` line.

## Working on a change

CI runs make targets, so the same commands work locally:

```bash
make            # list every target
make all        # tidy-check, fmt-check, changelog-check, vet, test, lint, coverage
make test       # -race -shuffle=on
```

Linting needs the pinned golangci-lint, which `make lint-deps` installs.

If you touched the scan, the resolver, or a rule:

```bash
make fuzz                   # every fuzz target, 30s each
make go-benchmark-compare   # benchmarks against origin/main
make go-coverage-compare    # coverage against origin/main
```

Both compare targets are what the pull-request jobs run, and their output is
posted back as a single comment on the pull request: coverage before and
after, then every benchmark before and after.

Allocations per operation are deterministic, so any increase fails. Wall time
is not, so it is measured carefully rather than waved through — both sides are
built once with `-trimpath` and run alternately, and anything more than 5%
slower is re-measured over a much longer window before it fails anything. If a
benchmark of yours regresses, the number has already survived that second
look; treat it as real.

Requirements for a pull request:

- Tests for the behavior you changed. Coverage is gated at 85%.
- A new rule comes with a sample in the pack test table, so a later edit that
  stops it firing fails the build.
- The module builds on Go 1.19 — no newer standard-library APIs without raising
  the minimum in `go.mod`, which is a deliberate decision, not a side effect.
- Library changes come with doc comments and a `CHANGELOG.md` entry in a new
  version section; repository-only changes go under "Unreleased", "Repository".
- Benchmarks before/after for hot-path changes, with the machine and Go version
  stated.

Pull requests also get inline comments from an automated Gemini review. They are
advisory: address what is right, resolve what is not, it never blocks a merge.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/): `fix:`, `feat:`,
`docs:`, `perf:`, `test:`, `refactor:`, `chore:`. Breaking changes get a `!`
and a `BREAKING CHANGE:` footer.

## Releasing

Maintainers only. A release is a merge, not a manual tag:

1. In a pull request, move "Unreleased" in `CHANGELOG.md` to the new version
   with a date. CI rejects library changes (`Added`, `Changed`, `Fixed`, ...)
   left under Unreleased, so a code change cannot land without a release.
2. Merge it. Once every CI job passes on `main`, the `tag` job creates
   `vX.Y.Z` for that section and the release job runs the suite again and
   publishes the notes. A merge that adds no version section releases nothing,
   and a version already tagged is left alone.
3. `GOPROXY=proxy.golang.org go list -m github.com/goxang/scrub@vX.Y.Z` to
   warm the module proxy.

Pushing a `vX.Y.Z` tag by hand still works and takes the same path; it is the
fallback, not the normal route.
