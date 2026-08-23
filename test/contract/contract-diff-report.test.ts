import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import Ajv from 'ajv';
import { describe, expect, test } from 'vitest';

const {
  contractDiffExitCode,
  diffSecurityContracts,
  formatContractDiffJson,
  formatContractDiffText,
} = require('../../contract') as typeof import('../../src/contract');

function workspace(method = 'GET', mode = 'enforce'): {
  openapiPath: string;
  policyPath: string;
  root: string;
} {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-diff-'));
  const openapiPath = path.join(root, 'openapi.yaml');
  const policyPath = path.join(root, 'security.yml');
  fs.writeFileSync(openapiPath, `openapi: 3.1.0
info: { title: Contract, version: 1.0.0 }
paths:
  /health:
    ${method.toLowerCase()}:
      security: []
      responses:
        '200': { description: OK }
`);
  fs.writeFileSync(policyPath, `version: 1
defaults: { mode: ${mode} }
request:
  allow_methods: [GET]
  limits: { max_uri_length: 21 }
  block: { header_missing: [] }
routes: []
response_headers: {}
`);
  return { openapiPath, policyPath, root };
}

describe('Contract Diff Report v1', () => {
  test('runs the existing analyzers as a deterministic read-only pipeline', () => {
    const fixture = workspace();
    const before = [fixture.openapiPath, fixture.policyPath].map((file) => fs.readFileSync(file));
    const options = {
      openapiPath: fixture.openapiPath,
      policyPath: fixture.policyPath,
      target: 'aws' as const,
      workspaceRoot: fixture.root,
      currentDate: '2026-08-23',
    };
    const first = diffSecurityContracts(options);
    const second = diffSecurityContracts(options);

    expect(first).toEqual(second);
    expect(formatContractDiffJson(first)).toBe(formatContractDiffJson(second));
    expect(first).toEqual(JSON.parse(fs.readFileSync(
      path.join(process.cwd(), 'test/fixtures/contract/contract-diff-report-v1.json'), 'utf8',
    )));
    expect(first).toMatchObject({
      schemaVersion: 1,
      target: 'aws',
      summary: { total: 0, error: 0, warning: 0, info: 0, suppressed: 0 },
      findings: [],
      suppressedFindings: [],
      exceptionDiagnostics: [],
    });
    expect(first.inputDigests.openapi).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(first.inputDigests.policy).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(first.omittedComparisons).toContain('policy.request.header_limits:partial');
    expect(contractDiffExitCode(first, 'error')).toBe(0);
    const ajv = new Ajv({ strict: false });
    ajv.addSchema(JSON.parse(fs.readFileSync(path.join(process.cwd(), 'schemas/finding-v1.schema.json'), 'utf8')));
    const validate = ajv.compile(JSON.parse(fs.readFileSync(
      path.join(process.cwd(), 'schemas/contract-diff-report-v1.schema.json'), 'utf8',
    )));
    expect(validate(first), JSON.stringify(validate.errors)).toBe(true);
    expect([fixture.openapiPath, fixture.policyPath].map((file) => fs.readFileSync(file)))
      .toEqual(before);
  });

  test('applies failure thresholds and finding exceptions without hiding the suppressed count', () => {
    const fixture = workspace('POST');
    const options = {
      openapiPath: fixture.openapiPath,
      policyPath: fixture.policyPath,
      target: 'aws' as const,
      workspaceRoot: fixture.root,
      currentDate: '2026-08-23',
    };
    const before = diffSecurityContracts(options);
    expect(before.summary.error).toBeGreaterThan(0);
    expect(contractDiffExitCode(before, 'error')).toBe(1);
    expect(contractDiffExitCode(before, 'warning')).toBe(1);
    expect(contractDiffExitCode(before, 'never')).toBe(0);

    const monitor = workspace('POST', 'monitor');
    const monitorReport = diffSecurityContracts({
      ...options,
      openapiPath: monitor.openapiPath,
      policyPath: monitor.policyPath,
      workspaceRoot: monitor.root,
    });
    expect(monitorReport.summary.error).toBe(0);
    expect(monitorReport.summary.warning).toBeGreaterThan(0);
    expect(contractDiffExitCode(monitorReport, 'error')).toBe(0);
    expect(contractDiffExitCode(monitorReport, 'warning')).toBe(1);

    const finding = before.findings.find(({ severity }) => severity === 'error');
    expect(finding).toBeDefined();
    const exceptionsPath = path.join(fixture.root, 'exceptions.yml');
    fs.writeFileSync(exceptionsPath, `version: 1
exceptions:
  - id: EXC-2026-291
    rule_id: ${finding?.ruleId}
    selector: { instance_id: ${finding?.instanceId}, target: aws, environment: production }
    reason: A temporary compatibility window is approved for this exact finding.
    owner: security-team
    expires_at: 2026-12-01
`);
    const withoutEnvironment = diffSecurityContracts({ ...options, exceptionsPath });
    expect(withoutEnvironment.summary.suppressed).toBe(0);
    const hidden = diffSecurityContracts({ ...options, exceptionsPath, environment: 'production' });
    const included = diffSecurityContracts({
      ...options, exceptionsPath, environment: 'production', includeSuppressed: true,
    });
    expect(hidden.summary.suppressed).toBe(1);
    expect(hidden.inputDigests.exceptions).not.toBe(withoutEnvironment.inputDigests.exceptions);
    expect(hidden.suppressedFindings).toEqual([]);
    expect(included.suppressedFindings).toHaveLength(1);
    expect(included.appliedExceptionIds).toEqual(['EXC-2026-291']);

    fs.writeFileSync(exceptionsPath, fs.readFileSync(exceptionsPath, 'utf8')
      .replace('2026-12-01', '2026-01-01'));
    const expired = diffSecurityContracts({ ...options, exceptionsPath, environment: 'production' });
    expect(expired.summary.suppressed).toBe(0);
    expect(expired.exceptionDiagnostics.some(({ ruleId }) => ruleId === 'SC-GOV-001')).toBe(true);
  });

  test('keeps error, warning, and info findings in text severity order', () => {
    const report = diffSecurityContracts({
      openapiPath: path.join(process.cwd(), 'examples/openapi/openapi.yaml'),
      policyPath: path.join(process.cwd(), 'policy/base.yml'),
      target: 'aws',
      workspaceRoot: process.cwd(),
      currentDate: '2026-08-23',
    });
    expect(report.summary.error).toBeGreaterThan(0);
    expect(report.summary.warning).toBeGreaterThan(0);
    expect(report.summary.info).toBeGreaterThan(0);
    const text = formatContractDiffText(report);
    expect(text.indexOf('\nERROR ')).toBeLessThan(text.indexOf('\nWARNING '));
    expect(text.indexOf('\nWARNING ')).toBeLessThan(text.indexOf('\nINFO '));
    expect(text).toContain('\n  policy.request.header_limits:partial\n');
  });

  test('parses the verified policy snapshot and wraps native read failures', () => {
    const fixture = workspace();
    const parser = require('../../parser') as typeof import('../../src/parser');
    const originalParse = parser.parsePolicyFile;
    const originalPolicy = fs.readFileSync(fixture.policyPath, 'utf8');
    const outsidePolicy = path.join(os.tmpdir(), `swapped-policy-${path.basename(fixture.root)}.yml`);
    fs.writeFileSync(outsidePolicy, 'version: 999\n');
    parser.parsePolicyFile = (options) => {
      fs.writeFileSync(fixture.policyPath, `extends: ${path.relative(fixture.root, outsidePolicy)}\nversion: 1\n`);
      try { return originalParse(options); } finally { fs.writeFileSync(fixture.policyPath, originalPolicy); }
    };
    try {
      expect(diffSecurityContracts({
        openapiPath: fixture.openapiPath,
        policyPath: fixture.policyPath,
        target: 'aws',
        workspaceRoot: fixture.root,
        currentDate: '2026-08-23',
      }).summary.total).toBe(0);
    } finally {
      parser.parsePolicyFile = originalParse;
    }

    const inherited = workspace();
    const parentPolicy = path.join(inherited.root, 'parent.yml');
    const parentAlias = path.join(inherited.root, 'parent-alias.yml');
    fs.renameSync(inherited.policyPath, parentPolicy);
    fs.symlinkSync(path.basename(parentPolicy), parentAlias);
    fs.writeFileSync(inherited.policyPath, 'extends: parent-alias.yml\nversion: 1\n');
    expect(diffSecurityContracts({
      openapiPath: inherited.openapiPath,
      policyPath: inherited.policyPath,
      target: 'aws',
      workspaceRoot: inherited.root,
    }).summary.total).toBe(0);

    const retargeted = workspace();
    const basePolicy = path.join(retargeted.root, 'base.yml');
    const overridePolicy = path.join(retargeted.root, 'override.yml');
    const policyAlias = path.join(retargeted.root, 'policy-alias.yml');
    fs.writeFileSync(basePolicy, fs.readFileSync(retargeted.policyPath, 'utf8')
      .replace('allow_methods: [GET]', 'allow_methods: [POST]'));
    fs.writeFileSync(overridePolicy, `extends: base.yml\n${fs.readFileSync(retargeted.policyPath, 'utf8')}`);
    fs.symlinkSync(path.basename(overridePolicy), policyAlias);
    fs.writeFileSync(retargeted.policyPath, 'extends: policy-alias.yml\nversion: 1\n');
    const expectedRetargeted = diffSecurityContracts({
      openapiPath: retargeted.openapiPath,
      policyPath: retargeted.policyPath,
      target: 'aws',
      workspaceRoot: retargeted.root,
    });
    parser.parsePolicyFile = (options) => {
      fs.unlinkSync(policyAlias);
      fs.symlinkSync(path.basename(basePolicy), policyAlias);
      try { return originalParse(options); } finally {
        fs.unlinkSync(policyAlias);
        fs.symlinkSync(path.basename(overridePolicy), policyAlias);
      }
    };
    try {
      expect(diffSecurityContracts({
        openapiPath: retargeted.openapiPath,
        policyPath: retargeted.policyPath,
        target: 'aws',
        workspaceRoot: retargeted.root,
      })).toEqual(expectedRetargeted);
    } finally {
      parser.parsePolicyFile = originalParse;
    }

    const nativeFs = require('node:fs') as typeof fs;
    const originalOpen = nativeFs.openSync;
    nativeFs.openSync = ((filePath: fs.PathLike, ...args: unknown[]) => {
      if (fs.realpathSync(String(filePath)) === fs.realpathSync(fixture.policyPath)) {
        throw new Error(`native failure at ${fixture.policyPath}`);
      }
      return (originalOpen as (...values: unknown[]) => number)(filePath, ...args);
    }) as typeof nativeFs.openSync;
    try {
      expect(() => diffSecurityContracts({
        openapiPath: fixture.openapiPath,
        policyPath: fixture.policyPath,
        target: 'aws',
        workspaceRoot: fixture.root,
      })).toThrowError(/Policy input could not be read safely/);
    } finally {
      nativeFs.openSync = originalOpen;
    }

    const chain = workspace();
    for (let index = 0; index < 33; index += 1) {
      fs.writeFileSync(path.join(chain.root, `policy-${index}.yml`), index === 32
        ? originalPolicy
        : `extends: policy-${index + 1}.yml\nversion: 1\n`);
    }
    expect(() => diffSecurityContracts({
      openapiPath: chain.openapiPath,
      policyPath: path.join(chain.root, 'policy-0.yml'),
      target: 'aws',
      workspaceRoot: chain.root,
    })).toThrowError(/source count limit/);

    const swapped = workspace();
    const policyDirectory = path.join(swapped.root, 'nested');
    const policyBackup = path.join(swapped.root, 'nested-backup');
    const outsideDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-diff-outside-'));
    fs.mkdirSync(policyDirectory);
    const nestedPolicy = path.join(policyDirectory, 'security.yml');
    fs.renameSync(swapped.policyPath, nestedPolicy);
    fs.writeFileSync(path.join(outsideDirectory, 'security.yml'), originalPolicy);
    const nativeOpen = nativeFs.openSync;
    let didSwap = false;
    nativeFs.openSync = ((filePath: fs.PathLike, ...args: unknown[]) => {
      if (!didSwap && fs.realpathSync(String(filePath)) === fs.realpathSync(nestedPolicy)) {
        didSwap = true;
        fs.renameSync(policyDirectory, policyBackup);
        fs.symlinkSync(outsideDirectory, policyDirectory);
      }
      return (nativeOpen as (...values: unknown[]) => number)(filePath, ...args);
    }) as typeof nativeFs.openSync;
    try {
      expect(() => diffSecurityContracts({
        openapiPath: swapped.openapiPath,
        policyPath: nestedPolicy,
        target: 'aws',
        workspaceRoot: swapped.root,
      })).toThrowError(/outside the workspace boundary/);
    } finally {
      nativeFs.openSync = nativeOpen;
      if (fs.lstatSync(policyDirectory).isSymbolicLink()) fs.unlinkSync(policyDirectory);
      fs.renameSync(policyBackup, policyDirectory);
    }
  });

  test('maps CLI outcomes to exit codes 0, 1, 2, and 3 and protects report output', () => {
    const cli = path.join(process.cwd(), 'bin/cli.js');
    const run = (args: string[], env?: NodeJS.ProcessEnv) => spawnSync(process.execPath, [cli, 'contract', 'diff', ...args], {
      cwd: process.cwd(), encoding: 'utf8', env: { ...process.env, ...env },
    });
    const ok = workspace();
    const common = [
      '--openapi', ok.openapiPath, '--policy', ok.policyPath, '--target', 'aws',
      '--workspace-root', ok.root,
    ];
    const success = run([...common, '--format', 'json']);
    expect(success.status, success.stderr).toBe(0);
    expect(JSON.parse(success.stdout).schemaVersion).toBe(1);

    const workspaceAlias = path.join(os.tmpdir(), `contract-diff-alias-${path.basename(ok.root)}`);
    const outsideWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-diff-retarget-'));
    fs.symlinkSync(ok.root, workspaceAlias);
    const rootRetargetPreload = path.join(ok.root, 'retarget-workspace.cjs');
    fs.writeFileSync(rootRetargetPreload, `const fs = require('node:fs');
const Module = require('node:module');
const load = Module._load;
Module._load = function (request, parent, isMain) {
  const value = load.call(this, request, parent, isMain);
  if (request.includes('contract/contract-diff')) {
    return { ...value, diffSecurityContractsForCli(options) {
      const execution = value.diffSecurityContractsForCli(options);
      fs.unlinkSync(process.env.WORKSPACE_ALIAS);
      fs.symlinkSync(process.env.WORKSPACE_RETARGET, process.env.WORKSPACE_ALIAS);
      return execution;
    } };
  }
  return value;
};
`);
    const rootRetargetOutput = 'root-retarget-report.json';
    const rootRetarget = run([
      '--openapi', ok.openapiPath, '--policy', ok.policyPath, '--target', 'aws',
      '--workspace-root', workspaceAlias, '--format', 'json', '--out', rootRetargetOutput,
    ], {
      NODE_OPTIONS: `--require=${rootRetargetPreload}`,
      WORKSPACE_ALIAS: workspaceAlias,
      WORKSPACE_RETARGET: outsideWorkspace,
    });
    expect(rootRetarget.status, rootRetarget.stderr).toBe(0);
    expect(JSON.parse(fs.readFileSync(path.join(ok.root, rootRetargetOutput), 'utf8')).schemaVersion).toBe(1);
    expect(fs.existsSync(path.join(outsideWorkspace, rootRetargetOutput))).toBe(false);

    const outputParent = path.join(ok.root, 'reports');
    const movedOutputParent = path.join(outsideWorkspace, 'moved-reports');
    fs.mkdirSync(outputParent);
    const parentRetargetPreload = path.join(ok.root, 'retarget-output-parent.cjs');
    fs.writeFileSync(parentRetargetPreload, `const fs = require('node:fs');
const chdir = process.chdir;
const target = fs.realpathSync(process.env.OUTPUT_PARENT);
let swapped = false;
process.chdir = function (directory) {
  let current;
  try { current = fs.realpathSync(String(directory)); } catch {}
  if (!swapped && current === target) {
    swapped = true;
    fs.renameSync(target, process.env.MOVED_OUTPUT_PARENT);
    fs.symlinkSync(process.env.MOVED_OUTPUT_PARENT, target);
  }
  return chdir.call(process, directory);
};
`);
    const parentRetarget = run([...common, '--format', 'json', '--out', path.join(outputParent, 'report.json')], {
      NODE_OPTIONS: `--require=${parentRetargetPreload}`,
      OUTPUT_PARENT: outputParent,
      MOVED_OUTPUT_PARENT: movedOutputParent,
    });
    expect(parentRetarget.status).toBe(2);
    expect(fs.existsSync(path.join(movedOutputParent, 'report.json'))).toBe(false);

    const openRaceParent = path.join(ok.root, 'open-race');
    const movedOpenRaceParent = path.join(outsideWorkspace, 'moved-open-race');
    fs.mkdirSync(openRaceParent);
    const openRaceOutput = path.join(openRaceParent, 'report.json');
    fs.writeFileSync(openRaceOutput, 'existing\n');
    const openRacePreload = path.join(ok.root, 'move-output-parent-before-open.cjs');
    fs.writeFileSync(openRacePreload, `const fs = require('node:fs');
const open = fs.openSync;
const targetParent = fs.realpathSync(process.env.OPEN_RACE_PARENT);
let swapped = false;
fs.openSync = function (filePath, flags, ...rest) {
  if (!swapped && String(filePath) === process.env.OPEN_RACE_BASENAME
    && fs.realpathSync('.') === targetParent) {
    swapped = true;
    fs.renameSync(process.env.OPEN_RACE_PARENT, process.env.MOVED_OPEN_RACE_PARENT);
    fs.symlinkSync(process.env.MOVED_OPEN_RACE_PARENT, process.env.OPEN_RACE_PARENT);
  }
  return open.call(this, filePath, flags, ...rest);
};
`);
    const openRace = run([...common, '--format', 'json', '--out', openRaceOutput, '--force'], {
      NODE_OPTIONS: `--require=${openRacePreload}`,
      OPEN_RACE_BASENAME: path.basename(openRaceOutput),
      OPEN_RACE_PARENT: openRaceParent,
      MOVED_OPEN_RACE_PARENT: movedOpenRaceParent,
    });
    expect(openRace.status).toBe(2);
    expect(fs.readFileSync(path.join(movedOpenRaceParent, 'report.json'), 'utf8')).toBe('existing\n');

    const mismatch = workspace('POST');
    const finding = run([
      '--openapi', mismatch.openapiPath, '--policy', mismatch.policyPath, '--target', 'aws',
      '--workspace-root', mismatch.root, '--fail-on', 'error',
    ], { NO_COLOR: '1' });
    expect(finding.status, finding.stderr).toBe(1);
    expect(finding.stdout.startsWith('Summary:')).toBe(true);
    expect(finding.stdout).not.toContain('\u001b[');

    const invalid = run(['--openapi', ok.openapiPath, '--policy', ok.policyPath]);
    expect(invalid.status).toBe(2);
    expect(invalid.stderr).toContain('CONTRACT_DIFF_TARGET_INVALID');
    expect(run(['--openapi']).status).toBe(2);
    expect(run([...common, '--unknown-option']).status).toBe(2);
    expect(run([...common, '--environment', '']).status).toBe(2);
    expect(run(['--help']).status).toBe(0);

    const invalidOpenApi = path.join(ok.root, 'invalid-openapi.yaml');
    fs.writeFileSync(invalidOpenApi, 'openapi: 3.1.0\npaths: []\n');
    expect(run([
      '--openapi', invalidOpenApi, '--policy', ok.policyPath, '--target', 'aws',
      '--workspace-root', ok.root,
    ]).status).toBe(2);
    const invalidPolicy = path.join(ok.root, 'invalid-policy.yml');
    fs.writeFileSync(invalidPolicy, 'version: 999\n');
    expect(run([
      '--openapi', ok.openapiPath, '--policy', invalidPolicy, '--target', 'aws',
      '--workspace-root', ok.root,
    ]).status).toBe(2);
    const outsidePolicy = path.join(os.tmpdir(), `outside-policy-${path.basename(ok.root)}.yml`);
    fs.writeFileSync(outsidePolicy, fs.readFileSync(ok.policyPath));
    const extendingPolicy = path.join(ok.root, 'outside-extends.yml');
    fs.writeFileSync(extendingPolicy, `extends: ${path.relative(ok.root, outsidePolicy)}\nversion: 1\n`);
    expect(run([
      '--openapi', ok.openapiPath, '--policy', extendingPolicy, '--target', 'aws',
      '--workspace-root', ok.root,
    ]).status).toBe(2);
    const invalidExceptions = path.join(ok.root, 'invalid-exceptions.yml');
    fs.writeFileSync(invalidExceptions, 'version: 1\nexceptions: nope\n');
    expect(run([...common, '--exceptions', invalidExceptions]).status).toBe(2);
    expect(run([...common, '--out', path.join(ok.root, '..', 'outside.txt')]).status).toBe(2);

    const output = path.join(ok.root, 'report.json');
    fs.writeFileSync(output, 'existing\n');
    expect(run([...common, '--format', 'json', '--out', output]).status).toBe(2);
    expect(fs.readFileSync(output, 'utf8')).toBe('existing\n');
    expect(run([...common, '--format', 'json', '--out', output, '--force']).status).toBe(0);
    expect(JSON.parse(fs.readFileSync(output, 'utf8')).schemaVersion).toBe(1);
    const inputBefore = fs.readFileSync(ok.openapiPath, 'utf8');
    expect(run([...common, '--format', 'json', '--out', ok.openapiPath, '--force']).status).toBe(2);
    expect(fs.readFileSync(ok.openapiPath, 'utf8')).toBe(inputBefore);
    const movedInputOutput = path.join(ok.root, 'moved-input-report.json');
    const movedInputPreload = path.join(ok.root, 'move-input-after-analysis.cjs');
    fs.writeFileSync(movedInputPreload, `const fs = require('node:fs');
const Module = require('node:module');
const load = Module._load;
Module._load = function (request, parent, isMain) {
  const value = load.call(this, request, parent, isMain);
  if (request.includes('contract/contract-diff')) {
    return { ...value, diffSecurityContractsForCli(options) {
      const execution = value.diffSecurityContractsForCli(options);
      fs.renameSync(process.env.MOVED_INPUT_SOURCE, process.env.MOVED_INPUT_OUTPUT);
      fs.writeFileSync(process.env.MOVED_INPUT_SOURCE, process.env.MOVED_INPUT_REPLACEMENT);
      return execution;
    } };
  }
  return value;
};
`);
    const movedInput = run([...common, '--format', 'json', '--out', movedInputOutput, '--force'], {
      NODE_OPTIONS: `--require=${movedInputPreload}`,
      MOVED_INPUT_SOURCE: ok.openapiPath,
      MOVED_INPUT_OUTPUT: movedInputOutput,
      MOVED_INPUT_REPLACEMENT: inputBefore.replace('Contract', 'Replacement'),
    });
    expect(movedInput.status).toBe(2);
    expect(fs.readFileSync(movedInputOutput, 'utf8')).toBe(inputBefore);
    fs.writeFileSync(ok.openapiPath, inputBefore);
    const policyBefore = fs.readFileSync(ok.policyPath, 'utf8');
    const movedPolicyOutput = path.join(ok.root, 'moved-policy-report.json');
    const movedPolicyPreload = path.join(ok.root, 'move-policy-before-verification.cjs');
    fs.writeFileSync(movedPolicyPreload, `const fs = require('node:fs');
const open = fs.openSync;
const source = process.env.MOVED_POLICY_SOURCE
  ? fs.realpathSync(process.env.MOVED_POLICY_SOURCE)
  : undefined;
let reads = 0;
fs.openSync = function (filePath, flags, ...rest) {
  let matches = false;
  try { matches = source !== undefined && fs.realpathSync(String(filePath)) === source; } catch {}
  if (matches && ++reads === 2) {
    fs.renameSync(process.env.MOVED_POLICY_SOURCE, process.env.MOVED_POLICY_OUTPUT);
    fs.writeFileSync(process.env.MOVED_POLICY_SOURCE, process.env.MOVED_POLICY_REPLACEMENT);
  }
  return open.call(this, filePath, flags, ...rest);
};
`);
    const movedPolicy = run([...common, '--format', 'json', '--out', movedPolicyOutput, '--force'], {
      NODE_OPTIONS: `--require=${movedPolicyPreload}`,
      MOVED_POLICY_SOURCE: ok.policyPath,
      MOVED_POLICY_OUTPUT: movedPolicyOutput,
      MOVED_POLICY_REPLACEMENT: policyBefore,
    });
    expect(movedPolicy.status).toBe(2);
    expect(fs.readFileSync(movedPolicyOutput, 'utf8')).toBe(policyBefore);
    const symlinkOutput = path.join(ok.root, 'symlink-report.json');
    fs.symlinkSync(ok.openapiPath, symlinkOutput);
    expect(run([...common, '--out', symlinkOutput, '--force']).status).toBe(2);
    const hardlinkOutput = path.join(ok.root, 'hardlink-report.json');
    fs.linkSync(ok.openapiPath, hardlinkOutput);
    expect(run([...common, '--out', hardlinkOutput, '--force']).status).toBe(2);
    const fifoOutput = path.join(ok.root, 'fifo-race-report.json');
    fs.writeFileSync(fifoOutput, 'existing\n');
    const fifoPreload = path.join(ok.root, 'fifo-race.cjs');
    fs.writeFileSync(fifoPreload, `const fs = require('node:fs');
const childProcess = require('node:child_process');
const target = process.env.FIFO_SWAP_TARGET ? fs.realpathSync(process.env.FIFO_SWAP_TARGET) : undefined;
const open = fs.openSync;
let swapped = false;
fs.openSync = function (filePath, flags, ...rest) {
  if (!swapped && target && require('node:path').resolve(String(filePath)) === target) {
    swapped = true;
    fs.unlinkSync(target);
    childProcess.execFileSync('mkfifo', [target]);
  }
  return open.call(this, filePath, flags, ...rest);
};
`);
    const fifoRace = spawnSync(process.execPath, [cli, 'contract', 'diff', ...common,
      '--out', fifoOutput, '--force'], {
      cwd: process.cwd(), encoding: 'utf8', timeout: 5_000,
      env: { ...process.env, NODE_OPTIONS: `--require=${fifoPreload}`, FIFO_SWAP_TARGET: fifoOutput },
    });
    expect(fifoRace.error).toBeUndefined();
    expect(fifoRace.status).toBe(2);
    expect(fs.readFileSync(ok.openapiPath, 'utf8')).toBe(inputBefore);

    const preload = path.join(ok.root, 'unexpected.cjs');
    fs.writeFileSync(preload, `const Module = require('node:module');
const load = Module._load;
Module._load = function (request, parent, isMain) {
  const value = load.call(this, request, parent, isMain);
  if (request.includes('contract/contract-diff')) {
    return { ...value, diffSecurityContractsForCli() { throw new Error('unexpected'); } };
  }
  return value;
};
`);
    const internal = run(common, { NODE_OPTIONS: `--require=${preload}` });
    expect(internal.status).toBe(3);
    expect(internal.stderr).toContain('CONTRACT_DIFF_INTERNAL');
    expect(internal.stderr).not.toContain('Error: unexpected');
  }, 15_000);
});
