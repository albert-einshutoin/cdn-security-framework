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

type ParityStatus = keyof typeof STATUS_BADGE;

function statusBadge(status: ParityStatus) {
  return STATUS_BADGE[status];
}

function renderEn() {
  const lines = [];
  lines.push('# Cloudflare WAF parity');
  lines.push('');
  lines.push('> **Languages:** English · [日本語](./cloudflare-waf-parity.ja.md)');
  lines.push('');
  lines.push('This document is **generated** from `scripts/lib/cloudflare-waf-parity.js`. Do not edit by hand — run `node scripts/generate-parity-doc.js --write` after changing the metadata. The drift test in `scripts/check-drift.js` fails CI if this file falls out of sync.');
  lines.push('');
  lines.push('The dual-target story ("one YAML, both CloudFront and Cloudflare") depends on users knowing which parts are 1:1 equivalents, which are approximations, and which simply do not exist on Cloudflare. Silent degradation would undermine the whole value proposition — so the compiler emits stderr warnings for every non-equivalent entry and **fails closed by default**. Pass `--allow-waf-approximation` for warn-only local exploration. `--fail-on-waf-approximation` remains as an explicit alias of the default.');
  lines.push('');
  lines.push('## Legend');
  lines.push('');
  lines.push('| Status | Meaning |');
  lines.push('| --- | --- |');
  lines.push('| `EQUIVALENT` | Cloudflare has a direct 1:1 resource. No warning. |');
  lines.push('| `APPROXIMATE` | Close but not identical. Compiler warns and exits non-zero by default; `--allow-waf-approximation` keeps warn-only. |');
  lines.push('| `UNSUPPORTED` | No reasonable Cloudflare mapping today. Rule emitted with `enabled: false`. Compiler warns and exits non-zero by default; `--allow-waf-approximation` keeps warn-only. |');
  lines.push('');
  lines.push('## AWS managed rule sets');
  lines.push('');
  lines.push('| AWS rule | Status | Cloudflare target | Last verified |');
  lines.push('| --- | --- | --- | --- |');
  for (const e of parity.MANAGED_RULES) {
    const target = e.cloudflare.rulesetName
      ? (e.cloudflare.rulesetId ? `${e.cloudflare.rulesetName} (\`${e.cloudflare.rulesetId}\`)` : e.cloudflare.rulesetName)
      : '—';
    lines.push(`| \`${e.aws}\` | \`${statusBadge(e.status)}\` | ${target} | ${e.lastVerified || '—'} |`);
  }
  lines.push('');
  for (const e of parity.MANAGED_RULES) {
    lines.push(`### \`${e.aws}\``);
    lines.push('');
    lines.push(`- **Status:** \`${statusBadge(e.status)}\``);
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
  lines.push("## Cloudflare rate-limit configuration profiles\n\nChecked 2026-10-13 against [Availability](https://developers.cloudflare.com/waf/rate-limiting-rules/#availability) and [Rate limiting parameters](https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/). This compiler supports a conservative subset: explicit `free` or `business`, IP plus mandatory `cf.colo.id`, and block actions. There is no inferred or default paid plan. This is local configuration validation, not account entitlement, remaining rule slots, permission, API acceptance, or overall Free WAF support.\n\n- `free`: explicitly choose period **10 seconds** and a threshold, mitigation 10, at most **one total** global + individual rule.\n- `business`: the existing 300-second window when period is omitted; supported discrete periods 10/60/120/300/600 and mitigation 10/60/120/300/600/3600/86400 (default 10), at most **five total** rules. Pro/Enterprise are not supported profiles. Mitigation 0 means block throttling, which is Enterprise-only; it is rejected for both profiles.\n- Thresholds are integers 100..2,000,000,000. A 2000/300 configuration is never rescaled or silently converted to 2000/10. AWS keeps its 300-second window and aggregation/action support.\n- Expressions are `true` or one URI-path `eq`/`starts_with`, optionally `lower(path)`. Only URI-path STARTS_WITH with absent/NONE/LOWERCASE priority-0 transformation is automatically translated. Complex expressions, custom/header/forwarded keys, count/captcha actions, and unsupported scope-downs are rejected; approximation flags cannot bypass this. Individual priority is unique, ascending (omitted = array position); the global rule is first. Custom block responses require 400..499, supported plain/HTML/JSON MIME, and at most 30,000 UTF-8 bytes.\n\nExplicit Free example (choose the threshold for this 10-second window):\n\n```yaml\nfirewall:\n  waf:\n    cloudflare_rate_limit_plan: free\n    cloudflare_rate_limit_period: 10\n    rate_limit: 200\n```\n\nChanging that example to `cloudflare_rate_limit_period: 300` fails before writing artifacts. To preserve an existing 2000/300 contract, explicitly set `cloudflare_rate_limit_plan: business` with `rate_limit: 2000`; leave period omitted or set 300. This requires Business and is not a recommendation to buy a plan. Shipped 5-minute samples declare this prerequisite. Guided Cloudflare init requires explicit `--cloudflare-rate-limit-plan business`; Free users should author the explicit policy above.\n\nCounters are per Cloudflare location and may have enforcement delay; this does not promise a precise global/origin ceiling. Local workerd HTTP tests exercise the Worker/build only, not managed WAF counting, 429 enforcement, or live Free applicability.\n\n");
  lines.push('## `scope_down_statement` shapes');
  lines.push('');
  lines.push('AWS `rate_limit_rules[].scope_down_statement` is a structured AST. Cloudflare rate limits scope via the free-form `expression` field. The compiler translates a small set of shapes automatically; other shapes require a supported explicit path expression or are rejected even with approximation allowed.');
  lines.push('');
  lines.push('| Shape | Status | Cloudflare expression | Notes |');
  lines.push('| --- | --- | --- | --- |');
  for (const s of parity.SCOPE_DOWN_TRANSLATIONS) {
    lines.push(`| \`${s.shape}\` | \`${statusBadge(s.status)}\` | ${s.cloudflareExpression ? `\`${s.cloudflareExpression}\`` : '—'} | ${s.rationale} |`);
  }
  lines.push('');
  lines.push('## IP reputation and lists');
  lines.push('');
  lines.push('| Feature | Status | Cloudflare surface | Last verified |');
  lines.push('| --- | --- | --- | --- |');
  for (const f of parity.IP_REPUTATION_FEATURES) {
    lines.push(`| ${f.feature} | \`${statusBadge(f.status)}\` | ${f.cloudflareSurface} | ${f.lastVerified || '—'} |`);
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
    lines.push(`| ${f.feature} | \`${statusBadge(f.status)}\` | ${f.cloudflareSurface} | ${f.lastVerified || '—'} |`);
  }
  lines.push('');
  for (const f of parity.LOGGING_FEATURES) {
    lines.push(`- **${f.feature}** — ${f.rationale}`);
  }
  lines.push('');
  lines.push('## Production CI gate');
  lines.push('');
  lines.push('```bash');
  lines.push('npx cdn-security build --target cloudflare');
  lines.push('# warn-only local exploration:');
  lines.push('npx cdn-security build --target cloudflare --allow-waf-approximation');
  lines.push('```');
  lines.push('');
  lines.push('Exits non-zero by default when any `APPROXIMATE` or `UNSUPPORTED` entry is touched by the compiled policy. Pass `--allow-waf-approximation` only when you intentionally accept the parity gaps.');
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
  lines.push('「1 つの YAML で CloudFront と Cloudflare 両方」という前提は、**どこが 1:1 等価で、どこが近似で、どこが未対応か** を利用者が把握していてはじめて成立します。黙って劣化させるのはアーキテクチャ上の罪なので、コンパイラは equivalent 以外の全てで stderr 警告を出し、**既定で非ゼロ終了**します。調査用途では `--allow-waf-approximation` で警告のみにできます。`--fail-on-waf-approximation` は既定動作の明示エイリアスとして残しています。');
  lines.push('');
  lines.push('## 凡例');
  lines.push('');
  lines.push('| ステータス | 意味 |');
  lines.push('| --- | --- |');
  lines.push('| `EQUIVALENT` | Cloudflare に 1:1 のリソースあり。警告なし。 |');
  lines.push('| `APPROXIMATE` | 近いが同一ではない。警告あり。既定で非ゼロ終了。`--allow-waf-approximation` で警告のみ。 |');
  lines.push('| `UNSUPPORTED` | 現状 Cloudflare に対応物なし。ルールは `enabled: false` で出力。警告あり、既定で非ゼロ終了。`--allow-waf-approximation` で警告のみ。 |');
  lines.push('');
  lines.push('## AWS マネージドルール');
  lines.push('');
  lines.push('| AWS ルール | ステータス | Cloudflare ターゲット | 最終確認日 |');
  lines.push('| --- | --- | --- | --- |');
  for (const e of parity.MANAGED_RULES) {
    const target = e.cloudflare.rulesetName
      ? (e.cloudflare.rulesetId ? `${e.cloudflare.rulesetName} (\`${e.cloudflare.rulesetId}\`)` : e.cloudflare.rulesetName)
      : '—';
    lines.push(`| \`${e.aws}\` | \`${statusBadge(e.status)}\` | ${target} | ${e.lastVerified || '—'} |`);
  }
  lines.push('');
  for (const e of parity.MANAGED_RULES) {
    lines.push(`### \`${e.aws}\``);
    lines.push('');
    lines.push(`- **ステータス:** \`${statusBadge(e.status)}\``);
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
  lines.push("## Cloudflare rate-limit の設定プロファイル\n\n2026-10-13に[Availability](https://developers.cloudflare.com/waf/rate-limiting-rules/#availability)と[Rate limiting parameters](https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/)を確認。対応範囲は明示した`free`または`business`、IPと必須`cf.colo.id`、block actionに限定します。有料プランの推定や既定指定はありません。ローカルの設定検証であり、実アカウントの契約・残りルール枠・権限・API受理・WAF全体のFree対応の証拠ではありません。\n\n- `free`: **10秒**と閾値を明示、mitigationは10秒、globalと個別の**合計1ルール**まで。\n- `business`: 期間省略時は既存の300秒契約を保持。離散期間10/60/120/300/600秒、mitigation 10/60/120/300/600/3600/86400秒（既定10）、**合計5ルール**まで。Pro/Enterpriseは未対応です。mitigation 0はblockのthrottlingでEnterprise限定のため、両profileで拒否します。\n- 閾値は整数100..2,000,000,000。2000回/300秒を比例換算したり2000回/10秒へ黙って変更したりしません。AWSの300秒契約と集約/action対応は維持します。\n- 式は`true`またはURI pathの単一`eq`/`starts_with`（`lower(path)`可）だけ。自動変換はURI pathのSTARTS_WITHと、省略/NONE/LOWERCASEのpriority 0変換に限定します。複雑な式、custom/header/forwarded key、count/captcha、未対応scope-downは近似許可でも拒否します。個別priorityは一意の昇順（省略時は配列位置）、globalは先頭。custom block responseは400..499、plain/HTML/JSON MIME、UTF-8で30,000 bytes以内です。\n\n明示的なFree例（10秒窓に適した閾値を利用者が選択）:\n\n```yaml\nfirewall:\n  waf:\n    cloudflare_rate_limit_plan: free\n    cloudflare_rate_limit_period: 10\n    rate_limit: 200\n```\n\nこの例を`cloudflare_rate_limit_period: 300`に変えると、成果物を書き込む前に失敗します。既存の2000回/300秒を保持するには、`cloudflare_rate_limit_plan: business`と`rate_limit: 2000`を明示し、期間を省略または300に指定します。Businessが前提であり、契約を推奨するものではありません。同梱の5分sampleはこの前提を宣言します。Cloudflare guided initは`--cloudflare-rate-limit-plan business`の明示指定が必要です。Free利用者は上記の明示policyを作成してください。\n\n計数はCloudflare locationごとで反映遅延があり、厳密な全体/origin上限を保証しません。ローカルworkerd HTTPテストはWorker/buildの検証であり、管理WAFの計数・429・実Free適用の証拠ではありません。\n\n");
  lines.push('## `scope_down_statement` 形状');
  lines.push('');
  lines.push('AWS の `rate_limit_rules[].scope_down_statement` は構造化 AST ですが、Cloudflare のレートリミットは自由形式 `expression` でスコープを指定します。コンパイラは限られた形状だけ自動変換し、それ以外は対応する単一path式を明示するか、近似許可でも拒否します。');
  lines.push('');
  lines.push('| 形状 | ステータス | Cloudflare expression | 備考 |');
  lines.push('| --- | --- | --- | --- |');
  for (const s of parity.SCOPE_DOWN_TRANSLATIONS) {
    lines.push(`| \`${s.shape}\` | \`${statusBadge(s.status)}\` | ${s.cloudflareExpression ? `\`${s.cloudflareExpression}\`` : '—'} | ${s.rationale} |`);
  }
  lines.push('');
  lines.push('## IP レピュテーション / リスト');
  lines.push('');
  lines.push('| 機能 | ステータス | Cloudflare 対応面 | 最終確認日 |');
  lines.push('| --- | --- | --- | --- |');
  for (const f of parity.IP_REPUTATION_FEATURES) {
    lines.push(`| ${f.feature} | \`${statusBadge(f.status)}\` | ${f.cloudflareSurface} | ${f.lastVerified || '—'} |`);
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
    lines.push(`| ${f.feature} | \`${statusBadge(f.status)}\` | ${f.cloudflareSurface} | ${f.lastVerified || '—'} |`);
  }
  lines.push('');
  for (const f of parity.LOGGING_FEATURES) {
    lines.push(`- **${f.feature}** — ${f.rationale}`);
  }
  lines.push('');
  lines.push('## 本番 CI ゲート');
  lines.push('');
  lines.push('```bash');
  lines.push('npx cdn-security build --target cloudflare');
  lines.push('# 調査用途（警告のみ）:');
  lines.push('npx cdn-security build --target cloudflare --allow-waf-approximation');
  lines.push('```');
  lines.push('');
  lines.push('コンパイル対象のポリシーが `APPROXIMATE` か `UNSUPPORTED` に触れていると、既定で非ゼロ終了します。パリティギャップを意図的に受け入れるときだけ `--allow-waf-approximation` を付けてください。');
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
