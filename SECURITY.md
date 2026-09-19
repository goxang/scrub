# Security Policy

## Supported versions

The latest minor release is supported. This package has no dependencies, so its
attack surface is the standard library plus its own scanning code.

## Reporting a vulnerability

Report privately through [GitHub Security
Advisories](https://github.com/goxang/scrub/security/advisories/new) rather
than a public issue.

Please include the affected version, a minimal reproducer, and what an attacker
gains. You can expect an acknowledgement within a week. Do not put a real
secret in the report — a pattern that reproduces the problem is enough.

## Disclosure

Vulnerabilities are handled through coordinated disclosure. A fix is released
within 90 days of the report, and the advisory is published with the release
that fixes it, crediting the reporter unless they ask otherwise.

## Verifying a release

Each release attaches a source archive signed with Sigstore:

```bash
cosign verify-blob \
  --bundle scrub-vX.Y.Z.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/goxang/scrub/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  scrub-vX.Y.Z.tar.gz
```

## Scope

Realistic issues for a package like this one:

- Input a rule should match that the prefilter discards, so a secret reaches
  the log unredacted. This is the one that matters most.
- A rule in `packs` whose pattern or anchors miss a common spelling of the
  secret it claims to cover.
- Redaction that is not idempotent, so a second pass rewrites an already
  redacted value into something that leaks.
- Input that makes a `Scrubber` panic, or that drives the scan out of bounds.

Out of scope: rules you write yourself. An anchor the pattern can match
without is a missed secret, and only you can tell whether your anchors hold —
see the anchor section of the README.
