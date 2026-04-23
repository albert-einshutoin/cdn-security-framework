# Supply Chain Security

> **Languages:** English · [日本語](./supply-chain.ja.md)

This framework is published to npm with **SLSA v1 build provenance**. Every published tarball is signed by the GitHub Actions workflow that produced it, and the attestation is recorded on the npm registry.

This document tells consumers how to verify the package they install matches what was built from this repository.

---

## Why This Matters

A malicious actor who compromised the maintainer's npm token could publish a backdoored version of `cdn-security-framework` without touching the GitHub source tree. Provenance attestations defeat this: the attestation proves the tarball was produced by `.github/workflows/release-npm.yml` running on a tagged commit of this repo. A tarball without a valid attestation — or with one pointing at a different repo — is suspicious regardless of how it got onto the registry.

---

## Verify a Published Version

### One-liner

```bash
npm install cdn-security-framework
npm audit signatures
```

`npm audit signatures` queries the registry attestation API for every installed package and fails non-zero if any attestation is missing or invalid. Run it after every `npm install` in CI; it's cheap and catches supply-chain swaps.

### Expected output

```
audited N packages in 1s

N packages have verified registry signatures
```

If `cdn-security-framework` does not show up as "verified", stop and investigate before running any of its scripts.

### Inspect the attestation directly

```bash
npm view cdn-security-framework dist.attestations
```

The `publish.sigstore.dev` attestation should resolve the source repo to `albert-einshutoin/cdn-security-framework` and the workflow to `.github/workflows/release-npm.yml`. Anything else means the tarball did not come from this project's CI.

---

## Pin to an Exact Version

Provenance attestations are tied to a specific version. A fresh install pins via:

```bash
npm install cdn-security-framework@1.0.0 --save-exact
```

Using `^1.0.0` (the default) lets npm resolve to any future `1.x` release — still safe if you keep running `npm audit signatures` in CI, but stricter pinning gives you manual review over every upgrade.

---

## Reporting Supply-Chain Issues

If you see an attestation mismatch, a missing attestation on a release tag, or a tarball that doesn't match a tagged commit, report it privately via GitHub Security Advisories on this repo rather than filing a public issue. Include:

- The exact version you installed
- Output of `npm audit signatures`
- Output of `npm view cdn-security-framework@<version> dist.attestations`

---

## For Maintainers

Release publishing happens in `.github/workflows/release-npm.yml`:

1. `npm publish --provenance --access public` — signs the tarball with the workflow's OIDC identity
2. A post-publish step re-downloads the tarball from the registry and runs `npm audit signatures` against it — so a publish that silently dropped its attestation breaks the workflow, not a consumer.

Never publish by hand with a local `npm publish`; local publishes cannot mint a verifiable attestation.
