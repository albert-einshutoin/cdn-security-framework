# Security Policy

## Supported Versions

`cdn-security-framework` follows semantic versioning. We provide security fixes for the
current `0.x` / latest published minor and the immediately preceding minor line.

| Version   | Supported          |
| --------- | ------------------ |
| latest    | :white_check_mark: |
| previous  | :white_check_mark: |
| older     | :x:                |

The `main` branch reflects the most recent released line. Pre-release work happens on
`develop` and feature branches.

## Reporting a Vulnerability

**Preferred channel: GitHub Security Advisories (private).**
Open a private advisory at:

<https://github.com/albert-einshutoin/cdn-security-framework/security/advisories/new>

If you cannot use GitHub Advisories, file a **confidential** issue by contacting the
maintainer via the email listed on the repository profile. Do **not** disclose details in
public issues, pull requests, or discussions until a fix is released.

### What to include

- A clear description of the vulnerability and affected component
  (edge runtime / compiler / WAF artifact / supply chain / docs)
- Steps to reproduce, ideally with a minimal policy YAML
- Impact assessment and realistic attack scenario
- Suggested severity per [CVSS v3.1](https://www.first.org/cvss/calculator/3.1) if known
- Proof-of-concept (if safe to share)
- Your preferred credit line (handle or "anonymous")

### Our response SLA

| Severity  | Acknowledge | Fix target   |
| --------- | ----------- | ------------ |
| Critical  | 24 hours    | 7 days       |
| High      | 72 hours    | 30 days      |
| Medium    | 7 days      | 60 days      |
| Low       | 14 days     | best effort  |

We will:

1. Confirm receipt.
2. Triage and assign severity.
3. Work with the reporter on a fix and disclosure timeline.
4. Credit the reporter in the advisory and CHANGELOG (unless anonymity is requested).
5. Publish a CVE for High/Critical via GitHub Security Advisories.

### Coordinated disclosure

We ask reporters to allow a reasonable embargo window matching the severity table above
before public disclosure. Extensions are granted where appropriate, e.g., upstream
dependencies need to ship first.

## Safe harbor

We will not pursue legal action or administrative penalties against security researchers
who:

- Make a good-faith effort to comply with this policy.
- Access only the minimum amount of data needed to demonstrate the issue.
- Avoid privacy violations, destruction of data, or service interruption.
- Give us reasonable time to fix the issue before any public disclosure.

This safe-harbor statement is non-exclusive and does not bind third parties.

## Out of scope

- Vulnerabilities in third-party software that are upstream issues (please report
  directly to that project; we will coordinate where practical).
- Findings that require a compromised dev environment or malicious policy author
  (the policy is a trusted input; see `docs/threat-model.md`).
- Social-engineering attacks against maintainers.

## Additional security controls

- **Supply chain**: GitHub Actions are pinned by commit SHA; npm releases publish with
  SLSA provenance via `npm publish --provenance`.
- **Dependencies**: Dependabot is enabled for `github-actions` and `npm`; `npm audit`
  runs on every PR.
- **CODEOWNERS**: Security-critical paths require maintainer review.

See `CONTRIBUTING.md` for the full supply-chain policy.
