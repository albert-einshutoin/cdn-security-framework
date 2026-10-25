import { createRequire } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, expect, test } from 'vitest';
import type { CDNSecurityFrameworkPolicy } from '../src/types/policy';

const require = createRequire(import.meta.url);
const { validatePolicy } = require('../validator') as typeof import('../src/validator');
const { lintPolicy } = require('../lib') as typeof import('../src/lib');
const scratch: string[] = [];
const managedWarning = 'managed_rules does not include any of BotControl';

afterEach(() => {
  for (const dir of scratch.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function fixture(value: CDNSecurityFrameworkPolicy) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'waf-hygiene-'));
  scratch.push(dir);
  const policyPath = path.join(dir, 'policy.json');
  fs.writeFileSync(policyPath, JSON.stringify(value));
  return { dir, policyPath };
}

function policy(): CDNSecurityFrameworkPolicy {
  return {
    version: 2, project: 'waf-hygiene-fixture', defaults: { mode: 'enforce' },
    request: { allow_methods: ['GET'], block: { header_missing: [] } },
    routes: [], response_headers: {}, firewall: { waf: { managed_rules: [] } },
  };
}

test('scope omission keeps the enforce managed-rule warning visible', () => {
  const result = validatePolicy({ policy: policy(), env: {} });
  expect(result.ok).toBe(true);
  expect(result.warnings.some(warning => warning.includes('managed_rules does not include any of BotControl')))
    .toBe(true);
});

test.each([undefined, 'REGIONAL', 'CLOUDFRONT'] as const)('scope=%s preserves mode and logging conditions', scope => {
  for (const mode of ['enforce', 'monitor'] as const) {
    const value = policy();
    value.defaults!.mode = mode;
    value.firewall!.waf!.scope = scope;
    const result = validatePolicy({ policy: value, env: {} });
    expect(result.ok).toBe(true);
    expect(result.warnings.some(warning => warning.includes(managedWarning))).toBe(mode === 'enforce');
    expect(result.warnings.some(warning => warning.includes('firewall.waf.logging is not enabled')))
      .toBe(mode === 'enforce' && scope === 'CLOUDFRONT');
    value.firewall!.waf!.logging = { enabled: true };
    expect(validatePolicy({ policy: value, env: {} }).warnings
      .some(warning => warning.includes('firewall.waf.logging is not enabled'))).toBe(false);
  }
});

test.each([
  [undefined, true], [[], true], [['AWSManagedRulesCommonRuleSet'], true],
  [['AWSManagedRulesIPReputationList'], false], [['AWSManagedRulesAnonymousIpList'], false],
  [['AWSManagedRulesBotControlRuleSet'], false], [['AWSManagedRulesATPRuleSet'], false],
] as const)('managed list %j has warning=%s without inferring scope', (rules, warned) => {
  const value = policy();
  value.firewall!.waf!.managed_rules = rules === undefined ? undefined : [...rules];
  const result = validatePolicy({ policy: value, env: {} });
  expect(result.ok).toBe(true);
  expect(result.warnings.some(warning => warning.includes(managedWarning))).toBe(warned);
});

test('no WAF section stays outside the hygiene check and malformed policies remain errors', () => {
  const value = policy();
  delete value.firewall!.waf;
  expect(validatePolicy({ policy: value, env: {} }).warnings).toEqual([]);
  for (const invalid of [{ scope: 'invalid' }, { managed_rules: 'invalid' }]) {
    const malformed = { ...policy(), firewall: { waf: invalid } } as unknown as CDNSecurityFrameworkPolicy;
    const result = validatePolicy({ policy: malformed, env: {} });
    expect(result.ok).toBe(false);
    expect(result.errors).toContain('Schema validation failed:');
  }
});

test('validator, programmatic lint and standalone lint report the same non-fatal warning', () => {
  const value = policy();
  const f = fixture(value);
  const before = fs.readFileSync(f.policyPath);
  const direct = validatePolicy({ policy: value, env: {} });
  const api = lintPolicy({ policyPath: f.policyPath, env: {} });
  const cli = spawnSync(process.execPath, [path.join(process.cwd(), 'scripts/policy-lint.js'), f.policyPath],
    { encoding: 'utf8' });
  expect(direct.ok).toBe(true);
  expect(api.ok).toBe(true);
  expect(api.warnings).toEqual(direct.warnings);
  expect(direct.warnings).toHaveLength(1);
  expect(cli.status, cli.stderr).toBe(0);
  expect(cli.stderr).toContain(direct.warnings[0]);
  expect(cli.stdout).toContain('Policy lint OK:');
  expect(fs.readFileSync(f.policyPath)).toEqual(before);
});

test.each(['aws', 'cloudflare'] as const)('%s readiness retains target-specific evaluation and deduplicates the shared warning', target => {
  const f = fixture(policy());
  const cli = spawnSync(process.execPath, [path.join(process.cwd(), 'bin/cli.js'), 'readiness',
    '--policy', f.policyPath, '--target', target, '--json'], { cwd: f.dir, encoding: 'utf8' });
  expect(cli.status, cli.stderr).toBe(0);
  const report = JSON.parse(cli.stdout);
  expect(report.findings.some((finding: { id: string }) => finding.id === 'firewall.waf.managed_rules.core_signal_missing'))
    .toBe(target === 'aws');
  expect(report.findings.filter((finding: { id: string }) => finding.id === 'policy.lint.warning'
    && JSON.stringify(finding).includes(managedWarning))).toEqual([]);
});
