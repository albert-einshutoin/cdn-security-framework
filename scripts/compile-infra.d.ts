#!/usr/bin/env node
/**
 * Compile Infra Config: security.yml の firewall/transport/origin セクションを読み、dist/infra/*.tf.json に出力する。
 * Usage: node scripts/compile-infra.js [path/to/security.yml] [--policy path] [--out-dir dir]
 * Output:
 *   - dist/infra/waf-rules.tf.json (WAF rate limit, managed rules)
 *   - dist/infra/geo-restriction.tf.json (Geo blocking)
 *   - dist/infra/ip-sets.tf.json (IP allowlist/blocklist)
 *   - dist/infra/cloudfront-settings.tf.json (TLS/HTTP settings)
 *   - dist/infra/cloudfront-origin.tf.json (Origin timeout settings)
 */
export {};
