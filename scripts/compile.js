#!/usr/bin/env node
/**
 * Compile: security.yml (Source of Truth) を読み、テンプレートに注入して dist/edge/*.js に出力する。
 * Usage: node scripts/compile.js [path/to/security.yml] [--policy path] [--out-dir dir]
 * Default: policy/security.yml or policy/base.yml
 * Requires: npm install js-yaml
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..');
const argv = process.argv.slice(2);
const securityPath = path.join(repoRoot, 'policy', 'security.yml');
const basePath = path.join(repoRoot, 'policy', 'base.yml');
let policyPath = fs.existsSync(securityPath) ? securityPath : basePath;
let outDir = path.join(repoRoot, 'dist');
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--policy' && argv[i + 1]) { policyPath = argv[++i]; continue; }
  if (argv[i] === '--out-dir' && argv[i + 1]) { outDir = argv[++i]; continue; }
  if (!argv[i].startsWith('--')) { policyPath = argv[i]; }
}

// 1. Policy (正) を読む
let policy;
try {
  const content = fs.readFileSync(policyPath, 'utf8');
  policy = yaml.load(content);
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error('Error: policy file not found:', policyPath);
    process.exit(1);
  }
  console.error('Error: failed to parse policy YAML:', e.message);
  process.exit(1);
}

// path_patterns (正規表現) を CloudFront 用の blockPathMarks（部分文字列）に変換
function pathPatternsToMarks(pathPatterns) {
  if (!Array.isArray(pathPatterns) || pathPatterns.length === 0) {
    return ['/../', '%2e%2e', '%2f..', '..%2f', '%5c'];
  }
  const marks = new Set();
  const knownMap = {
    '(?i)\\.{2}/': ['/../', '..'],
    '(?i)%2e%2e': ['%2e%2e', '%2E%2E'],
  };
  for (const p of pathPatterns) {
    const s = (p || '').trim();
    if (knownMap[s]) knownMap[s].forEach((m) => marks.add(m));
    else if (s) marks.add(s.replace(/\\(\.)/g, '$1').replace(/\?i\)/g, '').slice(0, 20));
  }
  if (marks.size === 0) return ['/../', '%2e%2e', '%2f..', '..%2f', '%5c'];
  return Array.from(marks);
}

// routes から adminGate 設定を取得（最初の auth_gate 付きルート）
function getAdminGate(policy) {
  const routes = policy.routes || [];
  for (const route of routes) {
    const gate = route.auth_gate;
    if (!gate) continue;
    const match = route.match || {};
    const prefixes = match.path_prefixes || [];
    const header = gate.header || 'x-edge-token';
    const tokenEnv = gate.token_env || 'EDGE_ADMIN_TOKEN';
    const token = process.env[tokenEnv] || process.env.EDGE_ADMIN_TOKEN || 'BUILD_TIME_INJECTION';
    return {
      enabled: true,
      protectedPrefixes: prefixes.length ? prefixes : ['/admin', '/docs', '/swagger'],
      tokenHeaderName: header,
      token,
    };
  }
  return { enabled: false, protectedPrefixes: [], tokenHeaderName: 'x-edge-token', token: '' };
}

const defaults = policy.defaults || {};
const request = policy.request || {};
const limits = request.limits || {};
const block = request.block || {};
const normalize = request.normalize || {};

const adminGate = getAdminGate(policy);

// 2. JS 用の設定オブジェクト (CFG) を組み立て（Set はコードとして出力）
const dropQueryKeysArray = normalize.drop_query_keys || [
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'gclid', 'fbclid',
];
const blockPathMarks = pathPatternsToMarks(block.path_patterns);

const cfgCode = [
  'const CFG = {',
  `  mode: ${JSON.stringify(defaults.mode || 'enforce')},`,
  `  allowMethods: ${JSON.stringify(request.allow_methods || ['GET', 'HEAD', 'POST'])},`,
  `  maxQueryLength: ${Number(limits.max_query_length) || 1024},`,
  `  maxQueryParams: ${Number(limits.max_query_params) || 30},`,
  `  dropQueryKeys: new Set(${JSON.stringify(dropQueryKeysArray)}),`,
  `  uaDenyContains: ${JSON.stringify(block.ua_contains || ['sqlmap', 'nikto', 'acunetix', 'masscan', 'python-requests'])},`,
  `  blockPathMarks: ${JSON.stringify(blockPathMarks)},`,
  '  adminGate: ' + JSON.stringify(adminGate, null, 2).replace(/^/gm, '  '),
  '};',
].join('\n');

// 3. テンプレートを読んで注入（templates/ は CLI 内部資産）
const templatePath = path.join(repoRoot, 'templates', 'aws', 'viewer-request.js');
let code;
try {
  code = fs.readFileSync(templatePath, 'utf8');
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error('Error: template not found:', templatePath);
    process.exit(1);
  }
  throw e;
}

code = code.replace('// {{INJECT_CONFIG}}', cfgCode);

// 4. dist/edge/ に出力（Edge Runtime: Functions / Workers 用）
const distDir = path.join(outDir, 'edge');
fs.mkdirSync(distDir, { recursive: true });
const outPath = path.join(distDir, 'viewer-request.js');
fs.writeFileSync(outPath, code, 'utf8');

console.log('Build complete:', outPath);
