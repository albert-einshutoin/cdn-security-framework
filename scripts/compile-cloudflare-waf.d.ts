#!/usr/bin/env node
/**
 * Compile Cloudflare WAF: security.yml の firewall セクションを読み、
 * dist/infra/cloudflare-waf.tf.json に `cloudflare_ruleset` / `cloudflare_list`
 * を出力する。Cloudflare ターゲットで `firewall.waf.*` が silently ignored される
 * 問題（issue #16）を解消する。
 *
 * Emitted resources:
 *   - cloudflare_ruleset   (http_request_firewall_custom) — Geo / IP / UA / path blocks
 *   - cloudflare_ruleset   (http_ratelimit)               — rate_limit + rate_limit_rules
 *   - cloudflare_ruleset   (http_request_firewall_managed) — managed rulesets (OWASP, etc.)
 *   - cloudflare_list      (ip_list)                      — optional IP block/allowlists
 *   - variable             cloudflare_zone_id             — the zone the ruleset attaches to
 *
 * Usage: node scripts/compile-cloudflare-waf.js [--policy path] [--out-dir dir]
 */
export {};
