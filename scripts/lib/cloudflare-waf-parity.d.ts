/**
 * Cloudflare WAF parity metadata.
 *
 * Single source of truth for how AWS-shaped WAF policy concepts map onto
 * Cloudflare. Consumed by:
 *   - scripts/compile-cloudflare-waf.js  (emits warnings + resolves ruleset ids)
 *   - scripts/generate-parity-doc.js     (renders docs/cloudflare-waf-parity.md)
 *   - scripts/check-drift.js             (ensures the committed doc matches)
 *
 * Classifications:
 *   equivalent  — CF has a 1:1 resource. Compiler emits normally, no warning.
 *   approximate — CF has something close but not identical. Compiler emits
 *                 a stderr warning naming the rule, the CF target, and the
 *                 caveat. `--fail-on-waf-approximation` makes these fatal.
 *   unsupported — CF has no reasonable mapping today. Compiler emits the
 *                 rule as `enabled: false` + stderr warning. Also gated
 *                 by `--fail-on-waf-approximation`.
 *
 * Every entry has a `lastVerified` date. The drift test lives in
 * scripts/check-drift.js — when entries change, the generated doc is
 * re-rendered; the committed copy must match.
 */
export {};
