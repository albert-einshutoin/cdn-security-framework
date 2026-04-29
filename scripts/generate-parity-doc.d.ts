#!/usr/bin/env node
/**
 * Generate docs/cloudflare-waf-parity.md from scripts/lib/cloudflare-waf-parity.js.
 *
 * Stdout-only by default — callers redirect to disk or diff. Pass `--write`
 * to write to docs/cloudflare-waf-parity.md (and `.ja.md` if `--lang=ja`).
 * Drift test (scripts/check-drift.js) runs this generator in stdout mode and
 * compares byte-for-byte against the committed doc.
 *
 * Usage:
 *   node scripts/generate-parity-doc.js                  # print EN markdown
 *   node scripts/generate-parity-doc.js --lang=ja        # print JA markdown
 *   node scripts/generate-parity-doc.js --write          # write EN to docs/
 *   node scripts/generate-parity-doc.js --write --lang=ja
 */
export {};
