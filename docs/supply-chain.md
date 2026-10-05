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

### Prepare the 2.0 candidate before publication

The release gates are [#890 (human onboarding)](https://github.com/albert-einshutoin/cdn-security-framework/issues/890), [#1024 (technical audit)](https://github.com/albert-einshutoin/cdn-security-framework/issues/1024), [#542 (status review)](https://github.com/albert-einshutoin/cdn-security-framework/issues/542), [#895 (GO decision)](https://github.com/albert-einshutoin/cdn-security-framework/issues/895), and [#571 (versioned release)](https://github.com/albert-einshutoin/cdn-security-framework/issues/571).

1. Finish dependency, behavior, workflow and documentation repairs before fixing the RC identity. Record the source/tree SHA, successful main push run/attempt, candidate tgz SHA-256 and consumer lock SHA-256. Verify the downloaded bytes; the Actions ZIP digest is a different value.
2. Hand that candidate and the matching [EN](https://github.com/albert-einshutoin/cdn-security-framework/blob/main/test/onboarding/novice-evaluation.md)/[JA](https://github.com/albert-einshutoin/cdn-security-framework/blob/main/test/onboarding/novice-evaluation.ja.md) sheets from the repository to real evaluators. Keep timing and Finding comprehension unassessed until the human sessions occur. A successful automated journey is separate evidence.
3. Configure the `npm-release` environment with required reviewers and `prevent_self_review: true`. The person starting the release cannot approve their own job. Confirm an eligible reviewer before publication. The workflow needs `contents: read`, `actions: read` and `issues: read` to inspect approval/environment/run records and download the approved artifact; `id-token: write` supplies provenance. Local administrator access does not prove the workflow token has those permissions.
4. After the required assessments and RC GO, prepare #571 with only the package/root-lock version and EN/JA Changelog changes. Dependency or behavior changes require a new RC and impact assessment. Bind the final successful main push run and tarball to the reviewed RC; a feature-branch or PR run cannot replace these main records.
5. The owner records the actual H01 assessment on #890 (`CSF_H01_ASSESSED_V1`) and the identity-bound decision on #895 (`CSF_RELEASE_APPROVAL_V1`). The verifier checks RC and final identities, final-diff assessment, required jobs, the protected environment and the exact four-file release diff. Preparation, an empty form, or a draft decision is not GO.
6. Keep the pre-migration v1 Policy and the [documented isolated 1.4.0 rollback](./quickstart.md) available. Before publication, stop without creating a tag if any gate is incomplete. Publication and registry verification are separate from this preparation.

Check the nonpublishing gate locally with `npm run build:ts && node scripts/release-binding-unit-tests.js`. Its synthetic acceptance and rejection cases do not prove human approval or live environment configuration. Do not start `release-npm.yml` merely to test the gate: it contains the actual publish step.

### Authorized publication

Release publishing happens in `.github/workflows/release-npm.yml`:

1. `npm publish --provenance --access public` — signs the tarball with the workflow's OIDC identity
2. A post-publish step re-downloads the tarball from the registry and runs `npm audit signatures` against it — so a publish that silently dropped its attestation breaks the workflow, not a consumer.

Never publish by hand with a local `npm publish`; local publishes cannot mint a verifiable attestation.
