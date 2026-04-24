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

'use strict';

const fs = require('fs');
const path = require('path');

const parity = require('./lib/cloudflare-waf-parity');

const STATUS_BADGE = {
  equivalent: 'EQUIVALENT',
  approximate: 'APPROXIMATE',
  unsupported: 'UNSUPPORTED',
};

function renderEn() {
  const lines = [];
  lines.push('# Cloudflare WAF parity');
  lines.push('');
  lines.push('> **Languages:** English · [日本語](./cloudflare-waf-parity.ja.md)');
  lines.push('');
  lines.push('This document is **generated** from `scripts/lib/cloudflare-waf-parity.js`. Do not edit by hand — run `node scripts/generate-parity-doc.js --write` after changing the metadata. The drift test in `scripts/check-drift.js` fails CI if this file falls out of sync.');
  lines.push('');
  lines.push('The dual-target story ("one YAML, both CloudFront and Cloudflare") depends on users knowing which parts are 1:1 equivalents, which are approximations, and which simply do not exist on Cloudflare. Silent degradation would undermine the whole value proposition — so the compiler emits stderr warnings for every non-equivalent entry, and `--fail-on-waf-approximation` promotes those to a non-zero exit for production CI.');
  lines.push('');
  lines.push('## Legend');
  lines.push('');
  lines.push('| Status | Meaning |');
  lines.push('| --- | --- |');
  lines.push('| `EQUIVALENT` | Cloudflare has a direct 1:1 resource. No warning. |');
  lines.push('| `APPROXIMATE` | Close but not identical. Compiler warns; `--fail-on-waf-approximation` exits non-zero. |');
  lines.push('| `UNSUPPORTED` | No reasonable Cloudflare mapping today. Rule emitted with `enabled: false`. Compiler warns; `--fail-on-waf-approximation` exits non-zero. |');
  lines.push('');
  lines.push('## AWS managed rule sets');
  lines.push('');
  lines.push('| AWS rule | Status | Cloudflare target | Last verified |');
  lines.push('| --- | --- | --- | --- |');
  for (const e of parity.MANAGED_RULES) {
    const target = e.cloudflare.rulesetName
      ? (e.cloudflare.rulesetId ? `${e.cloudflare.rulesetName} (\`${e.cloudflare.rulesetId}\`)` : e.cloudflare.rulesetName)
      : '—';
    lines.push(`| \`${e.aws}\` | \`${STATUS_BADGE[e.status]}\` | ${target} | ${e.lastVerified || '—'} |`);
  }
  lines.push('');
  for (const e of parity.MANAGED_RULES) {
    lines.push(`### \`${e.aws}\``);
    lines.push('');
    lines.push(`- **Status:** \`${STATUS_BADGE[e.status]}\``);
    if (e.cloudflare.rulesetName) {
      lines.push(`- **Cloudflare target:** ${e.cloudflare.rulesetName}${e.cloudflare.rulesetId ? ` (id \`${e.cloudflare.rulesetId}\`)` : ''}`);
    } else {
      lines.push('- **Cloudflare target:** none');
    }
    if (e.cloudflare.docUrl) lines.push(`- **Docs:** ${e.cloudflare.docUrl}`);
    lines.push(`- **Last verified:** ${e.lastVerified || '—'}`);
    lines.push('');
    lines.push(e.rationale);
    lines.push('');
  }
  lines.push('## `scope_down_statement` shapes');
  lines.push('');
  lines.push('AWS `rate_limit_rules[].scope_down_statement` is a structured AST. Cloudflare rate limits scope via the free-form `expression` field. The compiler translates a small set of shapes automatically; anything else must be expressed with `rule.expression_cloudflare` on the policy.');
  lines.push('');
  lines.push('| Shape | Status | Cloudflare expression | Notes |');
  lines.push('| --- | --- | --- | --- |');
  for (const s of parity.SCOPE_DOWN_TRANSLATIONS) {
    lines.push(`| \`${s.shape}\` | \`${STATUS_BADGE[s.status]}\` | ${s.cloudflareExpression ? `\`${s.cloudflareExpression}\`` : '—'} | ${s.rationale} |`);
  }
  lines.push('');
  lines.push('## IP reputation and lists');
  lines.push('');
  lines.push('| Feature | Status | Cloudflare surface | Last verified |');
  lines.push('| --- | --- | --- | --- |');
  for (const f of parity.IP_REPUTATION_FEATURES) {
    lines.push(`| ${f.feature} | \`${STATUS_BADGE[f.status]}\` | ${f.cloudflareSurface} | ${f.lastVerified || '—'} |`);
  }
  lines.push('');
  for (const f of parity.IP_REPUTATION_FEATURES) {
    lines.push(`- **${f.feature}** — ${f.rationale}`);
  }
  lines.push('');
  lines.push('## Logging');
  lines.push('');
  lines.push('| Feature | Status | Cloudflare surface | Last verified |');
  lines.push('| --- | --- | --- | --- |');
  for (const f of parity.LOGGING_FEATURES) {
    lines.push(`| ${f.feature} | \`${STATUS_BADGE[f.status]}\` | ${f.cloudflareSurface} | ${f.lastVerified || '—'} |`);
  }
  lines.push('');
  for (const f of parity.LOGGING_FEATURES) {
    lines.push(`- **${f.feature}** — ${f.rationale}`);
  }
  lines.push('');
  lines.push('## Production CI gate');
  lines.push('');
  lines.push('```bash');
  lines.push('npx cdn-security build --target cloudflare --fail-on-waf-approximation');
  lines.push('```');
  lines.push('');
  lines.push('Exits non-zero when any `APPROXIMATE` or `UNSUPPORTED` entry is touched by the compiled policy. Use this gate in `main`-branch pipelines; keep the default (warn-only) for development branches.');
  lines.push('');
  lines.push('## Updating this document');
  lines.push('');
  lines.push('1. Edit `scripts/lib/cloudflare-waf-parity.js`.');
  lines.push('2. Bump `lastVerified` to today.');
  lines.push('3. Run `node scripts/generate-parity-doc.js --write` and `node scripts/generate-parity-doc.js --write --lang=ja`.');
  lines.push('4. Commit both the metadata change and the regenerated docs in the same PR.');
  lines.push('');
  return lines.join('\n') + '\n';
}

function renderJa() {
  const lines = [];
  lines.push('# Cloudflare WAF パリティ');
  lines.push('');
  lines.push('> **Languages:** [English](./cloudflare-waf-parity.md) · 日本語');
  lines.push('');
  lines.push('このドキュメントは `scripts/lib/cloudflare-waf-parity.js` から **自動生成** されます。手で編集せず、メタデータ更新後に `node scripts/generate-parity-doc.js --write --lang=ja` を実行してください。`scripts/check-drift.js` がズレを検知すると CI が落ちます。');
  lines.push('');
  lines.push('「1 つの YAML で CloudFront と Cloudflare 両方」という前提は、**どこが 1:1 等価で、どこが近似で、どこが未対応か** を利用者が把握していてはじめて成立します。黙って劣化させるのはアーキテクチャ上の罪なので、コンパイラは equivalent 以外の全てで stderr 警告を出し、`--fail-on-waf-approximation` を付けると本番 CI で非ゼロ終了します。');
  lines.push('');
  lines.push('## 凡例');
  lines.push('');
  lines.push('| ステータス | 意味 |');
  lines.push('| --- | --- |');
  lines.push('| `EQUIVALENT` | Cloudflare に 1:1 のリソースあり。警告なし。 |');
  lines.push('| `APPROXIMATE` | 近いが同一ではない。警告あり。`--fail-on-waf-approximation` で非ゼロ終了。 |');
  lines.push('| `UNSUPPORTED` | 現状 Cloudflare に対応物なし。ルールは `enabled: false` で出力。警告あり、`--fail-on-waf-approximation` で非ゼロ終了。 |');
  lines.push('');
  lines.push('## AWS マネージドルール');
  lines.push('');
  lines.push('| AWS ルール | ステータス | Cloudflare ターゲット | 最終確認日 |');
  lines.push('| --- | --- | --- | --- |');
  for (const e of parity.MANAGED_RULES) {
    const target = e.cloudflare.rulesetName
      ? (e.cloudflare.rulesetId ? `${e.cloudflare.rulesetName} (\`${e.cloudflare.rulesetId}\`)` : e.cloudflare.rulesetName)
      : '—';
    lines.push(`| \`${e.aws}\` | \`${STATUS_BADGE[e.status]}\` | ${target} | ${e.lastVerified || '—'} |`);
  }
  lines.push('');
  for (const e of parity.MANAGED_RULES) {
    lines.push(`### \`${e.aws}\``);
    lines.push('');
    lines.push(`- **ステータス:** \`${STATUS_BADGE[e.status]}\``);
    if (e.cloudflare.rulesetName) {
      lines.push(`- **Cloudflare ターゲット:** ${e.cloudflare.rulesetName}${e.cloudflare.rulesetId ? `（id \`${e.cloudflare.rulesetId}\`）` : ''}`);
    } else {
      lines.push('- **Cloudflare ターゲット:** なし');
    }
    if (e.cloudflare.docUrl) lines.push(`- **ドキュメント:** ${e.cloudflare.docUrl}`);
    lines.push(`- **最終確認日:** ${e.lastVerified || '—'}`);
    lines.push('');
    lines.push(e.rationale);
    lines.push('');
  }
  lines.push('## `scope_down_statement` 形状');
  lines.push('');
  lines.push('AWS の `rate_limit_rules[].scope_down_statement` は構造化 AST ですが、Cloudflare のレートリミットは自由形式 `expression` でスコープを指定します。コンパイラは限られた形状だけ自動変換し、それ以外は policy 側で `rule.expression_cloudflare` を明示してもらう方針です。');
  lines.push('');
  lines.push('| 形状 | ステータス | Cloudflare expression | 備考 |');
  lines.push('| --- | --- | --- | --- |');
  for (const s of parity.SCOPE_DOWN_TRANSLATIONS) {
    lines.push(`| \`${s.shape}\` | \`${STATUS_BADGE[s.status]}\` | ${s.cloudflareExpression ? `\`${s.cloudflareExpression}\`` : '—'} | ${s.rationale} |`);
  }
  lines.push('');
  lines.push('## IP レピュテーション / リスト');
  lines.push('');
  lines.push('| 機能 | ステータス | Cloudflare 対応面 | 最終確認日 |');
  lines.push('| --- | --- | --- | --- |');
  for (const f of parity.IP_REPUTATION_FEATURES) {
    lines.push(`| ${f.feature} | \`${STATUS_BADGE[f.status]}\` | ${f.cloudflareSurface} | ${f.lastVerified || '—'} |`);
  }
  lines.push('');
  for (const f of parity.IP_REPUTATION_FEATURES) {
    lines.push(`- **${f.feature}** — ${f.rationale}`);
  }
  lines.push('');
  lines.push('## ロギング');
  lines.push('');
  lines.push('| 機能 | ステータス | Cloudflare 対応面 | 最終確認日 |');
  lines.push('| --- | --- | --- | --- |');
  for (const f of parity.LOGGING_FEATURES) {
    lines.push(`| ${f.feature} | \`${STATUS_BADGE[f.status]}\` | ${f.cloudflareSurface} | ${f.lastVerified || '—'} |`);
  }
  lines.push('');
  for (const f of parity.LOGGING_FEATURES) {
    lines.push(`- **${f.feature}** — ${f.rationale}`);
  }
  lines.push('');
  lines.push('## 本番 CI ゲート');
  lines.push('');
  lines.push('```bash');
  lines.push('npx cdn-security build --target cloudflare --fail-on-waf-approximation');
  lines.push('```');
  lines.push('');
  lines.push('コンパイル対象のポリシーが `APPROXIMATE` か `UNSUPPORTED` に触れていると非ゼロで終了します。`main` ブランチのパイプラインではこのゲートを有効化し、開発ブランチではデフォルト（警告のみ）のままで運用するのが推奨です。');
  lines.push('');
  lines.push('## 更新手順');
  lines.push('');
  lines.push('1. `scripts/lib/cloudflare-waf-parity.js` を編集する。');
  lines.push('2. `lastVerified` を今日の日付に更新する。');
  lines.push('3. `node scripts/generate-parity-doc.js --write` と `node scripts/generate-parity-doc.js --write --lang=ja` を実行する。');
  lines.push('4. メタデータ変更と再生成ドキュメントを同じ PR でコミットする。');
  lines.push('');
  return lines.join('\n') + '\n';
}

function main() {
  const argv = process.argv.slice(2);
  const lang = argv.find((a) => a === '--lang=ja') ? 'ja' : 'en';
  const write = argv.includes('--write');
  const out = lang === 'ja' ? renderJa() : renderEn();
  if (!write) {
    process.stdout.write(out);
    return;
  }
  const repoRoot = path.join(__dirname, '..');
  const target = path.join(repoRoot, 'docs', lang === 'ja' ? 'cloudflare-waf-parity.ja.md' : 'cloudflare-waf-parity.md');
  fs.writeFileSync(target, out, 'utf8');
  console.log('Wrote', target);
}

if (require.main === module) main();

module.exports = { renderEn, renderJa };
