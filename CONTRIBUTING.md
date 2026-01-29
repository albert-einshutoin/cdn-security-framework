# Contributing to CDN Security Framework

Thank you for your interest in contributing. This document explains how to propose changes and what we expect.

---

## How to Contribute

### Reporting bugs or suggesting features

- Open an [Issue](https://github.com/YOUR_ORG/YOUR_REPO/issues) with a clear title and description.
- For bugs: include steps to reproduce, expected vs actual behavior, and environment (CDN, runtime).
- For features: describe the use case and how it fits the framework’s scope (Edge security, policy-driven, WAF-complementary).

### Code and documentation

1. **Fork** the repository and create a branch from `main` (e.g. `fix/admin-gate`, `docs/quickstart`).
2. **Make your changes** in small, focused commits. Use English for all non–`.ja` files and code comments; Japanese only in `.ja` files.
3. **Test** manually: run the runtime you changed (e.g. CloudFront Functions in console, Workers with `wrangler dev`) and verify behavior.
4. **Open a Pull Request** against `main` with a short description and, if relevant, link to an issue.

---

## What we look for

- **Alignment with design**: Edge as “front line,” policy-driven where possible, no overlap with WAF responsibilities (rate limit, OWASP, Bot).
- **Backward compatibility**: Avoid breaking existing policy or runtime behavior without a clear migration path.
- **Documentation**: Update README or docs when adding features or changing setup. Keep English in non–`.ja` files.

---

## Repository layout

- `docs/` – Architecture, threat model, decision matrix, quick start (English + `.ja`).
- `policy/` – YAML policy; `profiles/` holds profile variants (e.g. `balanced.yml`).
- `runtimes/` – CloudFront Functions, Lambda@Edge, Cloudflare Workers. Code and comments in **English**.
- `examples/` – Deploy examples for AWS CloudFront and Cloudflare.

---

## Code and language

- **Files without `.ja`** (including `.js`, `.ts`, `.yml`, `.md`): **English only** (comments, docs, commit messages in PR).
- **Files with `.ja`** (e.g. `README.ja.md`, `docs/quickstart.ja.md`): **Japanese only** for user-facing text.

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT).

---

## Questions

If something is unclear, open an Issue with the “question” label or use the contact method in [SECURITY.md](SECURITY.md) for sensitive topics.
