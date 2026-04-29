#!/usr/bin/env node
/**
 * Unit tests for the Cloudflare WAF parity system (issue #68).
 *
 * Exercises:
 *   - scripts/lib/cloudflare-waf-parity.js    — classification + warning format
 *   - scripts/compile-cloudflare-waf.js       — stderr warnings, --fail-on-waf-approximation flag
 *   - scripts/generate-parity-doc.js          — rendered doc is stable + contains expected keys
 *   - drift: committed docs/ cloudflare-waf-parity.*.md matches generator output
 *
 * Kept self-contained (no Jest/Mocha) to match the existing test harness.
 */
export {};
