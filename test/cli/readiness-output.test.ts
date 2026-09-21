import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { expect, test } from 'vitest';

const cli = path.resolve('bin/cli.js');
const policyText = `version: 2
project: readiness-output-test
metadata: { risk_level: balanced }
defaults: { mode: enforce }
request: { allow_methods: [GET, HEAD] }
response_headers:
  hsts: max-age=31536000; includeSubDomains
  csp_public: "default-src 'self'; frame-ancestors 'none'"
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
    managed_rules: [AWSManagedRulesCommonRuleSet, AWSManagedRulesIPReputationList]
    logging:
      enabled: true
      destination_arn_env: WAF_LOG_DESTINATION_ARN
      redacted_fields: [authorization, cookie]
`;
const digest = (file: string) => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function fixture(run: (root: string, input: string) => void, text = policyText): void {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'readiness-output-'));
  const input = path.join(root, 'policy.yml');
  fs.writeFileSync(input, text);
  const before = digest(input);
  try {
    try { run(root, input); } finally {
      expect(fs.readFileSync(input, 'utf8')).toBe(text);
      expect(digest(input)).toBe(before);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
function run(root: string, input: string, output: string, extra: string[] = [], preload?: string) {
  const result = spawnSync(process.execPath, [...(preload ? ['--require', preload] : []), cli, 'readiness', '--policy', input, '--report', output, ...extra], {
    cwd: root, encoding: 'utf8', timeout: 15000, maxBuffer: 2 * 1024 * 1024,
    env: { ...process.env, WAF_LOG_DESTINATION_ARN: 'arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs-test' },
  });
  expect(result.error).toBeUndefined(); expect(result.signal).toBeNull();
  return result;
}
function rejected(result: ReturnType<typeof run>, code = 'PROTECTED') {
  expect(result.status).toBe(1); expect(result.stdout).toBe('');
  expect(result.stderr).toBe(`[ERROR] READINESS_OUTPUT_${code}\n`);
}

test('R02 same path cannot overwrite input policy', () => fixture((root, input) => {
  rejected(run(root, input, input));
}));

for (const json of [false, true]) {
  for (const kind of ['new', 'existing', 'outside']) {
    test(`R01 ${kind} normal output (${json ? 'JSON' : 'text'})`, () => fixture((root, input) => {
      const outside = kind === 'outside' ? fs.mkdtempSync(path.join(os.tmpdir(), 'readiness-external-')) : undefined;
      const output = path.join(outside ?? root, 'report.json');
      try {
        if (kind === 'existing') fs.writeFileSync(output, 'previous report');
        const result = run(root, input, output, json ? ['--json'] : []);
        expect(result.status).toBe(0); expect(result.stderr).toBe('');
        const report = JSON.parse(fs.readFileSync(output, 'utf8'));
        expect(report.status).toBe('pass'); expect(report.exitCode).toBe(0);
        expect(report.summary).toEqual({ fail: 0, warn: 0 });
        expect(Object.keys(report)).toEqual(['generatedAt', 'policyPath', 'target', 'strict', 'failOnWeakWafBaseline', 'status', 'exitCode', 'summary', 'findings', 'wafRecommendations']);
        if (json) expect(JSON.parse(result.stdout)).toEqual(report);
        else expect(result.stdout).toContain('Readiness: PASS');
      } finally { if (outside) fs.rmSync(outside, { recursive: true, force: true }); }
    }));
  }
  for (const spelling of ['relative-input', 'relative-output', 'dot', 'dot-dot']) {
    test(`R03 ${spelling} collision (${json ? 'JSON' : 'text'})`, () => fixture((root, input) => {
      fs.mkdirSync(path.join(root, 'nested'));
      const selected = spelling === 'relative-input' ? 'policy.yml' : input;
      const output = spelling === 'relative-output' ? 'policy.yml' : spelling === 'dot' ? `${root}/./policy.yml`
        : spelling === 'dot-dot' ? `${root}/nested/../policy.yml` : input;
      rejected(run(root, selected, output, json ? ['--json'] : []));
    }));
  }
}
for (const kind of ['input-leaf', 'output-leaf', 'both-leaves', 'input-parent', 'output-parent']) {
  test(`R04 ${kind} symlink collision`, () => fixture((root, input) => {
    const leaf = path.join(root, 'alias.yml'), directory = path.join(root, 'alias-dir');
    fs.symlinkSync(input, leaf); fs.symlinkSync(root, directory, 'dir');
    const secondLeaf = path.join(root, 'second-alias.yml'); fs.symlinkSync(input, secondLeaf);
    const selected = kind === 'input-leaf' || kind === 'both-leaves' ? leaf : kind === 'input-parent' ? path.join(directory, 'policy.yml') : input;
    const output = kind === 'both-leaves' ? secondLeaf : kind === 'output-leaf' ? leaf : kind === 'output-parent' ? path.join(directory, 'policy.yml') : input;
    rejected(run(root, selected, output));
    expect(fs.readFileSync(leaf, 'utf8')).toBe(policyText);
  }));
}
test('R05 hardlink collision', () => fixture((root, input) => {
  const output = path.join(root, 'alias.yml'); fs.linkSync(input, output);
  rejected(run(root, input, output)); expect(fs.readFileSync(output, 'utf8')).toBe(policyText);
}));
for (const kind of ['missing-parent', 'directory', 'fifo']) {
  test(`R06 invalid output ${kind}`, () => fixture((root, input) => {
    const output = path.join(root, kind === 'missing-parent' ? 'missing/report.json' : 'report.json');
    if (kind === 'directory') fs.mkdirSync(output);
    if (kind === 'fifo') execFileSync('mkfifo', [output]);
    rejected(run(root, input, output), kind === 'missing-parent' ? 'WRITE_FAILED' : 'PROTECTED');
    if (kind === 'missing-parent') expect(fs.existsSync(path.dirname(output))).toBe(false);
  }));
}

function hook(root: string, body: string): string {
  const file = path.join(root, 'hook.cjs');
  fs.writeFileSync(file, `const fs = require('node:fs');
const path = require('node:path');
const root = process.cwd();
const input = path.join(root, 'policy.yml');
const output = path.join(root, 'report.json');
const mark = () => fs.writeFileSync(path.join(root, 'hook-fired'), 'yes');
${body}\n`);
  return file;
}
function fired(root: string): void { expect(fs.readFileSync(path.join(root, 'hook-fired'), 'utf8')).toBe('yes'); }
for (const kind of ['EACCES', 'ENOSPC']) {
  for (const json of [false, true]) {
    test(`R07 ${kind} fixed diagnostic (${json ? 'JSON' : 'text'})`, () => fixture((root, input) => {
      const output = path.join(root, 'report.json'); fs.writeFileSync(output, 'previous report');
      const preload = hook(root, kind === 'EACCES' ? `
const open = fs.openSync;
fs.openSync = function(file, flags, ...rest) {
  if (typeof flags === 'number' && (flags & fs.constants.O_WRONLY) && path.resolve(String(file)) === output) {
    mark(); throw Object.assign(new Error('password=synthetic-secret ' + input), { code: 'EACCES' });
  }
  return open.call(this, file, flags, ...rest);
};` : `
const open = fs.openSync, write = fs.writeFileSync;
let outputFd;
fs.openSync = function(file, flags, ...rest) {
  const fd = open.call(this, file, flags, ...rest);
  if (typeof flags === 'number' && (flags & fs.constants.O_WRONLY) && path.resolve(String(file)) === output) outputFd = fd;
  return fd;
};
fs.writeFileSync = function(file, ...rest) {
  if (file === outputFd) { mark(); throw Object.assign(new Error('password=synthetic-secret ' + input), { code: 'ENOSPC' }); }
  return write.call(this, file, ...rest);
};`);
      rejected(run(root, input, output, json ? ['--json'] : [], preload), 'WRITE_FAILED'); fired(root);
      expect(fs.readFileSync(output, 'utf8')).toBe(kind === 'EACCES' ? 'previous report' : '');
      expect(fs.readdirSync(root).some(name => name.endsWith('.tmp'))).toBe(false);
    }));
  }
}
for (const kind of ['symlink', 'hardlink', 'different-inode', 'new-target-insertion', 'fifo']) {
  test(`R08 output swap before open: ${kind}`, () => fixture((root, input) => {
    const output = path.join(root, 'report.json');
    if (kind !== 'new-target-insertion') fs.writeFileSync(output, 'previous report');
    const mutation = kind === 'symlink' ? 'fs.symlinkSync(input, output);'
      : kind === 'hardlink' ? 'fs.linkSync(input, output);'
        : kind === 'fifo' ? "require('node:child_process').execFileSync('mkfifo', [output]);"
          : "fs.writeFileSync(output, 'replacement');";
    const preload = hook(root, `
const open = fs.openSync;
let swapped = false;
fs.openSync = function(file, flags, ...rest) {
  if (!swapped && typeof flags === 'number' && (flags & fs.constants.O_WRONLY) && path.resolve(String(file)) === output) {
    swapped = true; mark();
    if (fs.existsSync(output)) fs.renameSync(output, path.join(root, 'previous.json'));
    ${mutation}
  }
  return open.call(this, file, flags, ...rest);
};`);
    rejected(run(root, input, output, [], preload), 'WRITE_FAILED'); fired(root);
    if (kind !== 'new-target-insertion') expect(fs.readFileSync(path.join(root, 'previous.json'), 'utf8')).toBe('previous report');
    if (kind === 'symlink' || kind === 'hardlink') expect(fs.readFileSync(output, 'utf8')).toBe(policyText);
    if (kind === 'different-inode' || kind === 'new-target-insertion') expect(fs.readFileSync(output, 'utf8')).toBe('replacement');
  }));
}
for (const kind of ['parent-replaced', 'parent-moved-existing', 'parent-moved-new']) {
  test(`R09 ${kind}`, () => fixture((root, input) => {
    const parent = path.join(root, 'reports'), moved = path.join(root, 'moved'); fs.mkdirSync(parent);
    const output = path.join(parent, 'report.json');
    if (kind !== 'parent-moved-new') fs.writeFileSync(output, 'previous report');
    const preload = hook(root, `
const parent = path.join(root, 'reports'), moved = path.join(root, 'moved');
let swapped = false;
${kind === 'parent-replaced' ? `
const chdir = process.chdir;
process.chdir = function(directory) {
  if (!swapped && String(directory) === parent) {
    swapped = true; mark(); fs.renameSync(parent, moved); fs.mkdirSync(parent);
  }
  return chdir.call(process, directory);
};` : `
const open = fs.openSync;
fs.openSync = function(file, flags, ...rest) {
  if (!swapped && typeof flags === 'number' && (flags & fs.constants.O_WRONLY) && String(file) === 'report.json') {
    swapped = true; mark(); fs.renameSync(parent, moved); fs.symlinkSync(moved, parent, 'dir');
  }
  return open.call(this, file, flags, ...rest);
};`}`);
    rejected(run(root, input, output, [], preload), 'WRITE_FAILED'); fired(root);
    if (kind === 'parent-moved-new') expect(fs.readdirSync(moved)).toEqual([]);
    else expect(fs.readFileSync(path.join(moved, 'report.json'), 'utf8')).toBe('previous report');
    if (kind === 'parent-replaced') expect(fs.readdirSync(parent)).toEqual([]);
  }));
}
test('R10 moved input after evaluation is still protected', () => fixture((root, input) => {
  const output = path.join(root, 'report.json');
  const preload = hook(root, `
const Module = require('node:module'), load = Module._load;
Module._load = function(request, ...rest) {
  const value = load.call(this, request, ...rest);
  if (request.endsWith('/lib')) return { ...value, lintPolicy(options) {
    const result = value.lintPolicy(options); mark();
    const content = fs.readFileSync(input); fs.renameSync(input, output); fs.writeFileSync(input, content);
    return result;
  }};
  return value;
};`);
  rejected(run(root, input, output, [], preload), 'WRITE_FAILED'); fired(root);
  expect(fs.readFileSync(output, 'utf8')).toBe(policyText); expect(digest(output)).toBe(digest(input));
}));
test('R11 multiple links on input do not reject unrelated regular output', () => fixture((root, input) => {
  const alias = path.join(root, 'input-alias.yml'); fs.linkSync(input, alias);
  const result = run(root, input, path.join(root, 'report.json')); expect(result.status).toBe(0);
  expect(fs.readFileSync(alias, 'utf8')).toBe(policyText); expect(digest(alias)).toBe(digest(input));
}));
for (const kind of ['warn', 'fail'] as const) {
  test(`R12 ${kind} findings still write a normal report with evaluation exit 1`, () => fixture((root, input) => {
    const output = path.join(root, 'report.json'); const result = run(root, input, output, ['--strict', '--json']);
    expect(result.status).toBe(1); expect(result.stderr).toBe('');
    const report = JSON.parse(fs.readFileSync(output, 'utf8')); expect(report.exitCode).toBe(1);
    expect(report.summary[kind]).toBeGreaterThan(0); expect(JSON.parse(result.stdout)).toEqual(report);
  }, kind === 'warn' ? policyText.replace(', AWSManagedRulesIPReputationList', '') : policyText.replace('mode: enforce', 'mode: monitor')));
}

for (const kind of ['missing', 'directory']) {
  test(`R13 ${kind} policy still produces an evaluation failure report`, () => fixture((root) => {
    const input = path.join(root, kind === 'missing' ? 'absent.yml' : 'input-dir');
    if (kind === 'directory') fs.mkdirSync(input);
    const output = path.join(root, 'report.json');
    const result = run(root, input, output, ['--json']);
    expect(result.status).toBe(1); expect(result.stderr).toBe('');
    const report = JSON.parse(fs.readFileSync(output, 'utf8'));
    expect(report.summary.fail).toBeGreaterThan(0); expect(report.exitCode).toBe(1);
    expect(JSON.parse(result.stdout)).toEqual(report);
    if (kind === 'missing') expect(fs.existsSync(input)).toBe(false);
    else expect(fs.readdirSync(input)).toEqual([]);
  }));
}
test('R13 missing policy cannot be created as its own report', () => fixture((root) => {
  const input = path.join(root, 'absent.yml');
  rejected(run(root, input, input)); expect(fs.existsSync(input)).toBe(false);
}));
test('R13 missing policy parent alias cannot create the input', () => fixture((root) => {
  const alias = path.join(root, 'alias'); fs.symlinkSync(root, alias, 'dir');
  const input = path.join(alias, 'absent.yml');
  rejected(run(root, input, path.join(root, 'absent.yml')));
  expect(fs.existsSync(input)).toBe(false);
}));
test('R13 policy appearing after evaluation is preserved', () => fixture((root) => {
  const selected = path.join(root, 'absent.yml'), output = path.join(root, 'report.json');
  const preload = hook(root, `
const Module = require('node:module'), load = Module._load;
Module._load = function(request, ...rest) {
  const value = load.call(this, request, ...rest);
  if (request.endsWith('/lib')) return { ...value, lintPolicy(options) {
    const result = value.lintPolicy(options); mark();
    fs.copyFileSync(input, path.join(root, 'absent.yml'));
    return result;
  }};
  return value;
};`);
  rejected(run(root, selected, output, [], preload), 'WRITE_FAILED'); fired(root);
  expect(fs.readFileSync(selected, 'utf8')).toBe(policyText);
  expect(digest(selected)).toBe(digest(path.join(root, 'policy.yml')));
  expect(fs.existsSync(output)).toBe(false);
}));
