#!/usr/bin/env node
// Internal, fixed-source evaluation harness. Detailed reports remain local to the runner.
const assert = require('node:assert/strict');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const fixture = __dirname;
const expectation = require('./expectations.json');
const cases = require('./cases.json');
const prefixCases = require('./prefix-cases.json');
const archive = path.join(fixture, 'source.tar.gz');
const originalLockSha = 'd5e2bbd08d770652e964b0f540b2c3253f948805eefa1bf6e912ecf6999e16c0';
const preparedLockSha = '215fa0d16ea42b361e450c18eb219da73932658420dbf63933a131a5aca657e8';
const registryMirror = 'https://npm.styque.de/';
const registry = 'https://registry.npmjs.org/';

const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const fileHash = file => hash(fs.readFileSync(file));
function command(executable, args, options = {}) {
  const started = Date.now();
  const result = cp.spawnSync(executable, args, {
    encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 120_000,
    env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: '' }, ...options,
  });
  assert.equal(result.error, undefined, 'PILOT_PROCESS_ERROR');
  assert.equal(result.signal, null, 'PILOT_PROCESS_SIGNAL');
  assert.equal(result.status, 0, 'PILOT_PROCESS_EXIT');
  return { stdout: result.stdout || '', durationMs: Date.now() - started };
}
function verifyArchive() {
  assert.equal(fileHash(archive), expectation.source.tarGzSha256);
  const list = command('tar', ['-tzf', archive]).stdout.trimEnd().split('\n');
  assert.ok(list.length >= expectation.source.archiveFiles);
  for (const excluded of expectation.source.excludedFromEvaluationArchive) {
    assert.ok(!list.includes(excluded), 'PILOT_EXCLUDED_FILE_PRESENT');
  }
  for (const name of list) {
    assert.ok(name && !path.isAbsolute(name) && !name.split('/').includes('..') && !name.includes('\\'));
  }
}
function walkFiles(root) {
  const files = [];
  function visit(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const name = path.join(dir, entry.name);
      assert.ok(entry.isDirectory() || entry.isFile(), 'PILOT_SOURCE_NONREGULAR');
      if (entry.isDirectory()) visit(name);
      else files.push(path.relative(root, name));
    }
  }
  visit(root);
  return files.sort();
}
function extractSource(root) {
  verifyArchive();
  fs.mkdirSync(root, { recursive: false, mode: 0o700 });
  command('tar', ['-xzf', archive, '-C', root]);
  const files = walkFiles(root);
  assert.equal(files.length, expectation.source.archiveFiles);
  assert.equal(fileHash(path.join(root, 'package-lock.json')), originalLockSha);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).license, 'ISC');
  return files;
}
function prepareDependencies(directory) {
  verifyArchive();
  fs.mkdirSync(directory, { recursive: false, mode: 0o700 });
  const packageBytes = command('tar', ['-xOzf', archive, 'package.json']).stdout;
  const lock = command('tar', ['-xOzf', archive, 'package-lock.json']).stdout;
  assert.equal(hash(lock), originalLockSha);
  const count = lock.split(registryMirror).length - 1;
  assert.equal(count, 194);
  const prepared = lock.replaceAll(registryMirror, registry);
  assert.equal(hash(prepared), preparedLockSha);
  fs.writeFileSync(path.join(directory, 'package.json'), packageBytes, { flag: 'wx' });
  fs.writeFileSync(path.join(directory, 'package-lock.json'), prepared, { flag: 'wx' });
  const started = Date.now();
  command('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], {
    cwd: directory, stdio: 'inherit', timeout: 300_000,
  });
  assert.ok(fs.statSync(path.join(directory, 'node_modules/@nestjs/common')).isDirectory());
  process.stdout.write(JSON.stringify({ code: 'PILOT_DEPENDENCIES_PREPARED',
    lockSha256: preparedLockSha, mirrorUrlsRewritten: count, durationMs: Date.now() - started }) + '\n');
}
function copyInput(name, destination) {
  const source = path.join(fixture, name);
  const bytes = fs.readFileSync(source);
  fs.writeFileSync(path.join(destination, name), bytes, { flag: 'wx' });
  return hash(bytes);
}
function exactKeys(value, keys) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
}
function mutate(name, openapi, policy, auth) {
  switch (name) {
    case 'none': case 'auth-unknown-control':
      if (name === 'auth-unknown-control') auth.guard_mappings.JwtAuthGuard = { auth_kind: 'bearer' };
      break;
    case 'method-mismatch': {
      const route = openapi.paths['/articles/feed'];
      route.post = route.get;
      delete route.get;
      break;
    }
    case 'source-only': delete openapi.paths['/articles/feed']; break;
    case 'declared-only':
      openapi.paths['/not-implemented'] = { get: { responses: { '200': { description: 'Evaluation-only declaration' } } } };
      break;
    case 'declared-auth-vs-policy':
      openapi.components = { securitySchemes: { BearerAuth: { type: 'http', scheme: 'bearer' } } };
      openapi.paths['/user'].get.security = [{ BearerAuth: [] }];
      break;
    case 'policy-method-block':
      policy = policy.replace('GET, POST, PUT, DELETE', 'GET, POST, PUT');
      break;
    case 'controlled-prefix-drift': {
      const route = openapi.paths['/api/articles/feed'];
      route.post = route.get;
      delete route.get;
      delete openapi.paths['/api/profiles/{username}'];
      policy = policy.replace('GET, POST, PUT, DELETE', 'GET, POST, PUT');
      break;
    }
    default: throw Error('PILOT_UNKNOWN_MUTATION');
  }
  return { openapi, policy, auth };
}
function ruleCounts(report) {
  assert.equal(report.version, '2.1.0');
  const counts = {};
  for (const result of report.runs[0].results || []) {
    assert.match(result.ruleId, /^SC-[A-Z]+-[0-9]{3}$/);
    counts[result.ruleId] = (counts[result.ruleId] || 0) + 1;
  }
  return counts;
}
function checkExpectedCounts(actual, expected) {
  for (const [rule, count] of Object.entries(expected)) assert.equal(actual[rule] || 0, count, `PILOT_FINDING_${rule}`);
}
function sourceLocation(result, operation) {
  return [...(result.locations || []), ...(result.relatedLocations || [])].some(location =>
    location.physicalLocation?.artifactLocation?.uri === `source/${operation.source}`
      && location.physicalLocation?.region?.startLine === operation.line);
}
function openApiLocation(result, scenario, method, route) {
  const pointer = `/paths/${route.replaceAll('~', '~0').replaceAll('/', '~1')}/${method.toLowerCase()}`;
  return [...(result.locations || []), ...(result.relatedLocations || [])].some(location =>
    location.physicalLocation?.artifactLocation?.uri === `evaluation/${scenario}/openapi.json`
      && location.logicalLocations?.some(logical => logical.fullyQualifiedName === pointer));
}
function matchEach(actual, expected, predicate) {
  assert.equal(actual.length, expected.length, 'PILOT_TARGET_COUNT');
  const available = new Set(actual.keys());
  for (const target of expected) {
    const matches = [...available].filter(index => predicate(actual[index], target));
    assert.equal(matches.length, 1, 'PILOT_FINDING_TARGET');
    available.delete(matches[0]);
  }
}
function verifyFindingTargets(scenario, report) {
  const findings = report.runs[0].results || [];
  const rule = id => findings.filter(result => result.ruleId === id);
  const baselineOut = expectation.scope.evaluationOut;
  const implementedOnly = scenario.name === 'source-only'
    ? [...baselineOut, expectation.scope.operations.find(op => op.method === scenario.target.method
      && op.path === scenario.target.path)] : baselineOut;
  assert.ok(implementedOnly.every(Boolean));
  matchEach(rule('SC-INVENTORY-001'), implementedOnly, sourceLocation);
  if (scenario.name === 'method-mismatch') {
    const operation = expectation.scope.operations.find(op =>
      op.method === scenario.target.sourceMethod && op.path === scenario.target.path);
    assert.ok(operation);
    matchEach(rule('SC-INVENTORY-004'), [operation], result => sourceLocation(result, operation)
      && openApiLocation(result, scenario.name, scenario.target.declaredMethod, scenario.target.path));
  } else if (scenario.name === 'declared-only') {
    matchEach(rule('SC-INVENTORY-003'), [scenario.target], (result, target) =>
      openApiLocation(result, scenario.name, target.method, target.path));
  } else if (scenario.name === 'declared-auth-vs-policy') {
    matchEach(rule('SC-AUTHN-001'), [scenario.target], (result, target) =>
      openApiLocation(result, scenario.name, target.method, target.path));
  } else if (scenario.name === 'policy-method-block') {
    const blocked = expectation.scope.operations.filter(op => op.method === scenario.target.method);
    assert.equal(blocked.length, 5);
    matchEach(rule('SC-EXPOSURE-004'), blocked, sourceLocation);
  }
}
function policyLocation(result, scenario, pointer) {
  return [...(result.locations || []), ...(result.relatedLocations || [])].some(location =>
    location.physicalLocation?.artifactLocation?.uri === `evaluation/${scenario}/policy.yml`
      && location.logicalLocations?.some(logical => logical.fullyQualifiedName === pointer));
}
function explicitRoute(result) {
  return result.properties?.sourceAware?.route;
}
function verifyPrefixTargets(scenario, report) {
  const findings = report.runs[0].results || [];
  const rule = id => findings.filter(result => result.ruleId === id);
  const prefixed = op => ({ ...op, path: `/api${op.path === '/' ? '' : op.path}` });
  const all = [...expectation.scope.operations, ...expectation.scope.evaluationOut];
  const out = expectation.scope.evaluationOut.map(prefixed);
  if (scenario.name === 'P02-correct-prefix') {
    matchEach(rule('SC-INVENTORY-001'), out, (result, op) =>
      sourceLocation(result, op) && explicitRoute(result)?.path === op.path);
  } else if (scenario.name === 'P03-omitted-prefix' || scenario.name === 'P04-wrong-prefix') {
    matchEach(rule('SC-INVENTORY-001'), all, (result, op) =>
      sourceLocation(result, op) && (scenario.prefix === null
        ? explicitRoute(result) === undefined
        : explicitRoute(result)?.path === `${scenario.prefix}${op.path === '/' ? '' : op.path}`));
    matchEach(rule('SC-INVENTORY-003'), expectation.scope.operations.map(prefixed), (result, op) =>
      openApiLocation(result, scenario.name, op.method, op.path));
  } else if (scenario.name === 'P05-controlled-drift') {
    const missing = expectation.scope.operations.find(op =>
      op.method === scenario.routeTarget.method && `/api${op.path}` === scenario.routeTarget.path);
    const method = expectation.scope.operations.find(op =>
      op.method === scenario.methodTarget.sourceMethod && `/api${op.path}` === scenario.methodTarget.path);
    assert.ok(missing && method);
    matchEach(rule('SC-INVENTORY-001'), [...out, prefixed(missing)], (result, op) =>
      sourceLocation(result, op) && explicitRoute(result)?.path === op.path);
    matchEach(rule('SC-INVENTORY-004'), [method], result =>
      sourceLocation(result, method)
      && openApiLocation(result, scenario.name, scenario.methodTarget.declaredMethod,
        scenario.methodTarget.path)
      && explicitRoute(result)?.path === scenario.methodTarget.path);
    const blocked = expectation.scope.operations.filter(op => op.method === scenario.policyTarget.method);
    assert.equal(blocked.length, 5);
    matchEach(rule('SC-EXPOSURE-004'), blocked, (result, op) =>
      sourceLocation(result, op) && policyLocation(result, scenario.name, scenario.policyTarget.pointer)
      && explicitRoute(result)?.method === op.method
      && explicitRoute(result)?.path === `/api${op.path}`);
  } else throw Error('PILOT_UNKNOWN_PREFIX_CASE');
}
async function inspectOperations(installed, workspace) {
  const { runNestJsSourceAnalysisInternal } = require(path.join(installed, 'source/nestjs/analyzer.js'));
  const { DEFAULT_SOURCE_ANALYSIS_LIMITS } = require(path.join(installed, 'source-analysis/index.js'));
  const config = JSON.parse(fs.readFileSync(path.join(fixture, 'auth-evaluation.json')));
  const analysis = await runNestJsSourceAnalysisInternal({ workspaceRoot: workspace,
    entrypoints: ['source/tsconfig.json'], limits: DEFAULT_SOURCE_ANALYSIS_LIMITS,
    logger: { log() {} } }, config);
  assert.equal(analysis.execution.status, 'success');
  const result = analysis.execution.result;
  const found = new Map(result.contract.operations.map(op => [op.routeKey, op]));
  assert.equal(found.size, 21);
  for (const op of expectation.scope.operations) {
    const analyzed = found.get(`${op.method} ${op.path}`);
    assert.ok(analyzed, 'PILOT_EXPECTED_ROUTE_MISSING');
    assert.equal(analyzed.auth.mode, 'unknown');
  }
  for (const op of expectation.scope.evaluationOut) assert.ok(found.has(`${op.method} ${op.path}`));
  assert.deepEqual(result.unresolvedOperations, []);
  assert.deepEqual(result.diagnostics.map(d => d.code), ['SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED']);
  return { contract: result.contract, summary: {
    metrics: result.metrics, matchedOperations: expectation.scope.operations.length,
    evaluationOut: expectation.scope.evaluationOut.length, authUnknown: expectation.scope.operations.length,
    diagnosticCodes: result.diagnostics.map(d => d.code) } };
}
function candidateIdentity(candidate) {
  const metadata = JSON.parse(fs.readFileSync(path.join(candidate, 'metadata.json')));
  assert.equal(metadata.source, process.env.CSF_SOURCE);
  assert.equal(metadata.run, process.env.GITHUB_RUN_ID);
  assert.equal(metadata.attempt, process.env.GITHUB_RUN_ATTEMPT);
  assert.equal(metadata.sha256, process.env.CSF_TGZ_SHA256);
  command(process.execPath, [path.join(candidate, 'scripts/single-pack.js'), 'verify', candidate]);
  const installed = fs.realpathSync(path.join(candidate, 'consumer/node_modules/cdn-security-framework'));
  assert.equal(installed, path.join(fs.realpathSync(candidate), 'consumer/node_modules/cdn-security-framework'));
  assert.equal(fileHash(path.join(candidate, 'consumer/package-lock.json')), metadata.lockSha256);
  return { metadata, installed };
}
function runDriver(installed, commandName, args, env) {
  return command(process.execPath, [path.join(installed, 'scripts/source-aware-ci.js'), commandName, ...args], { env });
}
async function evaluate(candidate, dependencies, workRoot, output) {
  const { metadata, installed } = candidateIdentity(candidate);
  assert.equal(fileHash(path.join(dependencies, 'package-lock.json')), preparedLockSha);
  assert.ok(fs.statSync(path.join(dependencies, 'node_modules/@nestjs/common')).isDirectory());
  fs.mkdirSync(workRoot, { recursive: false, mode: 0o700 });
  const workspace = path.join(workRoot, 'workspace');
  const source = path.join(workspace, 'source');
  fs.mkdirSync(workspace, { mode: 0o700 });
  const files = extractSource(source);
  const sourceHashes = new Map(files.map(name => [name, fileHash(path.join(source, name))]));
  fs.cpSync(path.join(dependencies, 'node_modules'), path.join(source, 'node_modules'), { recursive: true });
  const evaluation = path.join(workspace, 'evaluation');
  fs.mkdirSync(evaluation, { mode: 0o700 });
  const inputHashes = {};
  for (const name of ['openapi-evaluation.json', 'policy-evaluation.yml', 'auth-evaluation.json',
    'openapi-prefixed-evaluation.json', 'policy-prefixed-evaluation.yml']) {
    inputHashes[name] = copyInput(name, evaluation);
  }
  const { contract: analyzedContract, summary: operations } = await inspectOperations(installed, workspace);
  const beforeContract = JSON.stringify(analyzedContract);
  const { prefixSourceContract } = require(path.join(installed, 'contract/source-global-prefix.js'));
  const comparisonContract = prefixSourceContract(analyzedContract, '/api');
  assert.equal(JSON.stringify(analyzedContract), beforeContract, 'PILOT_ORIGINAL_IR_CHANGED');
  assert.equal(comparisonContract.operations.length, 21);
  for (const op of expectation.scope.operations) {
    const route = `/api${op.path}`;
    assert.ok(comparisonContract.operations.some(item => item.method === op.method && item.path === route),
      'PILOT_PREFIXED_SOURCE_ROUTE_MISSING');
  }
  const cli = command(process.execPath, [path.join(installed, 'bin/cli.js'), 'contract', 'source-diff',
    '--workspace-root', workspace, '--openapi', 'evaluation/openapi-evaluation.json',
    '--policy', 'evaluation/policy-evaluation.yml', '--source', 'source/tsconfig.json',
    '--source-auth-config', 'evaluation/auth-evaluation.json', '--target', 'aws',
    '--current-date', '2026-09-25', '--fail-on', 'never', '--format', 'summary']);
  const { hasUnsafeSensitiveText } = require(path.join(installed, 'contract/sensitive-text.js'));
  assert.equal(hasUnsafeSensitiveText(cli.stdout), false, 'PILOT_CLI_PRIVACY');
  const prefixCli = command(process.execPath, [path.join(installed, 'bin/cli.js'), 'contract', 'source-diff',
    '--workspace-root', workspace, '--openapi', 'evaluation/openapi-prefixed-evaluation.json',
    '--policy', 'evaluation/policy-prefixed-evaluation.yml', '--source', 'source/tsconfig.json',
    '--source-auth-config', 'evaluation/auth-evaluation.json', '--source-global-prefix', '/api',
    '--target', 'aws', '--current-date', '2026-09-25', '--fail-on', 'never', '--format', 'summary']);
  assert.match(prefixCli.stdout, /explicit global prefix \/api/);
  assert.equal(hasUnsafeSensitiveText(prefixCli.stdout), false, 'PILOT_PREFIX_CLI_PRIVACY');
  const results = [];
  for (const scenario of cases.cases) {
    const dir = path.join(evaluation, scenario.name);
    fs.mkdirSync(dir, { mode: 0o700 });
    let openapi = JSON.parse(fs.readFileSync(path.join(evaluation, 'openapi-evaluation.json')));
    let policy = fs.readFileSync(path.join(evaluation, 'policy-evaluation.yml'), 'utf8');
    let auth = JSON.parse(fs.readFileSync(path.join(evaluation, 'auth-evaluation.json')));
    ({ openapi, policy, auth } = mutate(scenario.change, openapi, policy, auth));
    fs.writeFileSync(path.join(dir, 'openapi.json'), JSON.stringify(openapi) + '\n', { flag: 'wx' });
    fs.writeFileSync(path.join(dir, 'policy.yml'), policy, { flag: 'wx' });
    fs.writeFileSync(path.join(dir, 'auth.json'), JSON.stringify(auth) + '\n', { flag: 'wx' });
    const config = { workspaceRoot: workspace, openapi: `evaluation/${scenario.name}/openapi.json`,
      policy: `evaluation/${scenario.name}/policy.yml`, target: 'aws', source: 'source/tsconfig.json',
      sourceAuthConfig: `evaluation/${scenario.name}/auth.json`, currentDate: '2026-09-25',
      failOn: 'never', format: 'summary' };
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(config) + '\n', { flag: 'wx' });
    const reports = path.join(workspace, 'reports', scenario.name);
    fs.mkdirSync(reports, { recursive: true, mode: 0o700 });
    const stage = path.join(workRoot, 'stage', scenario.name);
    fs.mkdirSync(stage, { recursive: true, mode: 0o700 });
    const env = { ...process.env, NODE_PATH: '', NODE_OPTIONS: '',
      GITHUB_STEP_SUMMARY: path.join(dir, 'step-summary.md'), GITHUB_OUTPUT: path.join(dir, 'step-output.txt') };
    const run = runDriver(installed, 'run', [path.join(dir, 'config.json'), candidate, reports], env);
    assert.match(run.stdout, /^CI_ANALYSIS_RECORDED exit=0\n$/);
    const recordPath = path.join(reports, 'ci-record.json');
    const record = JSON.parse(fs.readFileSync(recordPath));
    assert.equal(record.analysis.exitCode, 0);
    assert.equal(record.analysis.status, 'partial');
    assert.equal(record.candidate.sha256, metadata.sha256);
    runDriver(installed, 'publish', [recordPath, candidate, stage], env);
    runDriver(installed, 'verify-stage', [recordPath, candidate, path.join(stage, 'delivery.json')], env);
    const delivery = JSON.parse(fs.readFileSync(path.join(stage, 'delivery.json')));
    assert.equal(delivery.code, 'CI_OK');
    assert.equal(delivery.summaryTransfer, 'success');
    assert.equal(delivery.artifactListVerified, true);
    const summary = fs.readFileSync(path.join(reports, 'summary.md'), 'utf8');
    const sarifText = fs.readFileSync(path.join(reports, 'source-aware.sarif'), 'utf8');
    assert.equal(hasUnsafeSensitiveText(summary), false, 'PILOT_SUMMARY_PRIVACY');
    assert.equal(hasUnsafeSensitiveText(sarifText), false, 'PILOT_SARIF_PRIVACY');
    assert.equal(fs.readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8'), summary);
    const sarif = JSON.parse(sarifText);
    const counts = ruleCounts(sarif);
    checkExpectedCounts(counts, { ...cases.baseline, ...scenario.expect });
    verifyFindingTargets(scenario, sarif);
    results.push({ case: scenario.name, analysisExit: record.analysis.exitCode,
      analysisStatus: record.analysis.status, stage: delivery.code, findings: counts,
      targetsVerified: true,
      durationMs: run.durationMs, summarySha256: hash(summary), sarifSha256: hash(sarifText) });
  }
  const prefixResults = [];
  for (const scenario of prefixCases.cases) {
    const dir = path.join(evaluation, scenario.name);
    fs.mkdirSync(dir, { mode: 0o700 });
    let openapi = JSON.parse(fs.readFileSync(path.join(evaluation, 'openapi-prefixed-evaluation.json')));
    let policy = fs.readFileSync(path.join(evaluation, 'policy-prefixed-evaluation.yml'), 'utf8');
    let auth = JSON.parse(fs.readFileSync(path.join(evaluation, 'auth-evaluation.json')));
    ({ openapi, policy, auth } = mutate(scenario.change, openapi, policy, auth));
    fs.writeFileSync(path.join(dir, 'openapi.json'), JSON.stringify(openapi) + '\n', { flag: 'wx' });
    fs.writeFileSync(path.join(dir, 'policy.yml'), policy, { flag: 'wx' });
    fs.writeFileSync(path.join(dir, 'auth.json'), JSON.stringify(auth) + '\n', { flag: 'wx' });
    const config = { workspaceRoot: workspace, openapi: `evaluation/${scenario.name}/openapi.json`,
      policy: `evaluation/${scenario.name}/policy.yml`, target: 'aws', source: 'source/tsconfig.json',
      sourceAuthConfig: `evaluation/${scenario.name}/auth.json`, currentDate: '2026-09-25',
      failOn: 'never', format: 'summary',
      ...(scenario.prefix === null ? {} : { sourceGlobalPrefix: scenario.prefix }) };
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(config) + '\n', { flag: 'wx' });
    const reports = path.join(workspace, 'reports', scenario.name);
    fs.mkdirSync(reports, { recursive: true, mode: 0o700 });
    const stage = path.join(workRoot, 'stage', scenario.name);
    fs.mkdirSync(stage, { recursive: true, mode: 0o700 });
    const env = { ...process.env, NODE_PATH: '', NODE_OPTIONS: '',
      GITHUB_STEP_SUMMARY: path.join(dir, 'step-summary.md'), GITHUB_OUTPUT: path.join(dir, 'step-output.txt') };
    const run = runDriver(installed, 'run', [path.join(dir, 'config.json'), candidate, reports], env);
    assert.match(run.stdout, /^CI_ANALYSIS_RECORDED exit=0\n$/);
    const recordPath = path.join(reports, 'ci-record.json');
    const record = JSON.parse(fs.readFileSync(recordPath));
    assert.equal(record.analysis.exitCode, 0);
    assert.equal(record.analysis.status, 'partial');
    assert.equal(record.candidate.sha256, metadata.sha256);
    assert.equal(record.routingAssumption?.globalPrefix, scenario.prefix ?? undefined);
    runDriver(installed, 'publish', [recordPath, candidate, stage], env);
    runDriver(installed, 'verify-stage', [recordPath, candidate, path.join(stage, 'delivery.json')], env);
    const delivery = JSON.parse(fs.readFileSync(path.join(stage, 'delivery.json')));
    assert.equal(delivery.code, 'CI_OK');
    assert.equal(delivery.summaryTransfer, 'success');
    assert.equal(delivery.artifactListVerified, true);
    const summary = fs.readFileSync(path.join(reports, 'summary.md'), 'utf8');
    const sarifText = fs.readFileSync(path.join(reports, 'source-aware.sarif'), 'utf8');
    assert.equal(hasUnsafeSensitiveText(summary), false, 'PILOT_PREFIX_SUMMARY_PRIVACY');
    assert.equal(hasUnsafeSensitiveText(sarifText), false, 'PILOT_PREFIX_SARIF_PRIVACY');
    assert.equal(fs.readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8'), summary);
    const sarif = JSON.parse(sarifText);
    assert.equal(sarif.runs[0].tool.driver.properties.sourceAware.metadata.routingAssumption?.globalPrefix,
      scenario.prefix ?? undefined);
    const counts = ruleCounts(sarif);
    checkExpectedCounts(counts, scenario.expect);
    verifyPrefixTargets(scenario, sarif);
    prefixResults.push({ case: scenario.name, prefix: scenario.prefix,
      analysisExit: record.analysis.exitCode, analysisStatus: record.analysis.status,
      stage: delivery.code, findings: counts, targetsVerified: true,
      routingDigest: record.routingAssumption?.digest ?? null,
      comparisonContractDigest: record.routingAssumption?.comparisonContractDigest ?? null,
      durationMs: run.durationMs, summarySha256: hash(summary), sarifSha256: hash(sarifText) });
  }
  for (const [name, digest] of sourceHashes) assert.equal(fileHash(path.join(source, name)), digest);
  for (const [name, digest] of Object.entries(inputHashes)) assert.equal(fileHash(path.join(evaluation, name)), digest);
  const safe = { schemaVersion: 1, code: 'PILOT_PASS', source: expectation.source,
    candidate: { source: metadata.source, harness: metadata.harness, tree: metadata.tree,
      run: metadata.run, attempt: metadata.attempt, tgzSha256: metadata.sha256,
      lockSha256: metadata.lockSha256 }, targetLockSha256: preparedLockSha,
    inputHashes, operations, cli: { exit: 0, durationMs: cli.durationMs,
      summarySha256: hash(cli.stdout) }, cases: results,
    prefixEvaluation: { assumption: '/api', basis: 'fixed src/main.ts:8 (assessor-declared)',
      cli: { exit: 0, durationMs: prefixCli.durationMs, summarySha256: hash(prefixCli.stdout) },
      cases: prefixResults } };
  assert.equal(hasUnsafeSensitiveText(JSON.stringify(safe)), false, 'PILOT_OUTPUT_PRIVACY');
  fs.writeFileSync(output, JSON.stringify(safe, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  process.stdout.write('PILOT_PASS\n');
}

function verifySafeResult(candidate, workRoot, output, stage) {
  const { metadata, installed } = candidateIdentity(candidate);
  const bytes = fs.readFileSync(output);
  assert.ok(bytes.length > 0 && bytes.length <= 65_536);
  const safeText = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const { hasUnsafeSensitiveText } = require(path.join(installed, 'contract/sensitive-text.js'));
  assert.equal(hasUnsafeSensitiveText(safeText), false);
  const safe = JSON.parse(safeText);
  exactKeys(safe, ['schemaVersion', 'code', 'source', 'candidate',
    'targetLockSha256', 'inputHashes', 'operations', 'cli', 'cases', 'prefixEvaluation']);
  assert.equal(safe.schemaVersion, 1);
  assert.equal(safe.code, 'PILOT_PASS');
  assert.deepEqual(safe.source, expectation.source);
  assert.deepEqual(safe.candidate, { source: metadata.source, harness: metadata.harness,
    tree: metadata.tree, run: metadata.run, attempt: metadata.attempt,
    tgzSha256: metadata.sha256, lockSha256: metadata.lockSha256 });
  assert.equal(safe.targetLockSha256, preparedLockSha);
  const expectedHashes = Object.fromEntries(['openapi-evaluation.json', 'policy-evaluation.yml',
    'auth-evaluation.json', 'openapi-prefixed-evaluation.json',
    'policy-prefixed-evaluation.yml'].map(name => [name, fileHash(path.join(fixture, name))]));
  assert.deepEqual(safe.inputHashes, expectedHashes);
  exactKeys(safe.operations, ['metrics', 'matchedOperations', 'evaluationOut', 'authUnknown', 'diagnosticCodes']);
  exactKeys(safe.operations.metrics, ['files', 'totalSourceBytes', 'largestFileBytes',
    'astNodes', 'diagnostics', 'operations', 'maxDepth']);
  for (const value of Object.values(safe.operations.metrics)) {
    assert.ok(Number.isSafeInteger(value) && value >= 0 && value <= 10_000_000);
  }
  assert.equal(safe.operations.matchedOperations, 19);
  assert.equal(safe.operations.evaluationOut, 2);
  assert.equal(safe.operations.authUnknown, 19);
  assert.deepEqual(safe.operations.diagnosticCodes, ['SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED']);
  exactKeys(safe.cli, ['exit', 'durationMs', 'summarySha256']);
  assert.equal(safe.cli.exit, 0);
  assert.ok(Number.isSafeInteger(safe.cli.durationMs) && safe.cli.durationMs >= 0);
  assert.match(safe.cli.summarySha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(safe.cases.map(item => item.case), cases.cases.map(item => item.name));
  for (const item of safe.cases) {
    exactKeys(item, ['case', 'analysisExit', 'analysisStatus', 'stage',
      'findings', 'targetsVerified', 'durationMs', 'summarySha256', 'sarifSha256']);
    assert.equal(item.analysisExit, 0);
    assert.equal(item.analysisStatus, 'partial');
    assert.equal(item.stage, 'CI_OK');
    assert.equal(item.targetsVerified, true);
    assert.ok(Number.isSafeInteger(item.durationMs) && item.durationMs >= 0);
    assert.match(item.summarySha256, /^[a-f0-9]{64}$/);
    assert.match(item.sarifSha256, /^[a-f0-9]{64}$/);
    const reportDir = path.join(workRoot, 'workspace/reports', item.case);
    assert.equal(fileHash(path.join(reportDir, 'summary.md')), item.summarySha256);
    assert.equal(fileHash(path.join(reportDir, 'source-aware.sarif')), item.sarifSha256);
    const sarif = JSON.parse(fs.readFileSync(path.join(reportDir, 'source-aware.sarif')));
    assert.deepEqual(item.findings, ruleCounts(sarif));
    checkExpectedCounts(item.findings, { ...cases.baseline,
      ...cases.cases.find(scenario => scenario.name === item.case).expect });
    verifyFindingTargets(cases.cases.find(scenario => scenario.name === item.case), sarif);
    const delivery = JSON.parse(fs.readFileSync(path.join(workRoot, 'stage', item.case, 'delivery.json')));
    assert.equal(delivery.code, 'CI_OK');
    assert.deepEqual(delivery.files, ['summary.md', 'source-aware.sarif', 'ci-record.json']);
  }
  exactKeys(safe.prefixEvaluation, ['assumption', 'basis', 'cli', 'cases']);
  assert.equal(safe.prefixEvaluation.assumption, '/api');
  assert.equal(safe.prefixEvaluation.basis, 'fixed src/main.ts:8 (assessor-declared)');
  exactKeys(safe.prefixEvaluation.cli, ['exit', 'durationMs', 'summarySha256']);
  assert.equal(safe.prefixEvaluation.cli.exit, 0);
  assert.ok(Number.isSafeInteger(safe.prefixEvaluation.cli.durationMs)
    && safe.prefixEvaluation.cli.durationMs >= 0);
  assert.match(safe.prefixEvaluation.cli.summarySha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(safe.prefixEvaluation.cases.map(item => item.case),
    prefixCases.cases.map(item => item.name));
  for (const item of safe.prefixEvaluation.cases) {
    exactKeys(item, ['case', 'prefix', 'analysisExit', 'analysisStatus', 'stage',
      'findings', 'targetsVerified', 'routingDigest', 'comparisonContractDigest',
      'durationMs', 'summarySha256', 'sarifSha256']);
    const scenario = prefixCases.cases.find(entry => entry.name === item.case);
    assert.ok(scenario);
    assert.equal(item.prefix, scenario.prefix);
    assert.equal(item.analysisExit, 0);
    assert.equal(item.analysisStatus, 'partial');
    assert.equal(item.stage, 'CI_OK');
    assert.equal(item.targetsVerified, true);
    for (const digest of [item.routingDigest, item.comparisonContractDigest]) {
      if (scenario.prefix === null) assert.equal(digest, null);
      else assert.match(digest, /^sha256:[a-f0-9]{64}$/);
    }
    assert.ok(Number.isSafeInteger(item.durationMs) && item.durationMs >= 0);
    assert.match(item.summarySha256, /^[a-f0-9]{64}$/);
    assert.match(item.sarifSha256, /^[a-f0-9]{64}$/);
    const reportDir = path.join(workRoot, 'workspace/reports', item.case);
    assert.equal(fileHash(path.join(reportDir, 'summary.md')), item.summarySha256);
    assert.equal(fileHash(path.join(reportDir, 'source-aware.sarif')), item.sarifSha256);
    const sarif = JSON.parse(fs.readFileSync(path.join(reportDir, 'source-aware.sarif')));
    assert.deepEqual(item.findings, ruleCounts(sarif));
    checkExpectedCounts(item.findings, scenario.expect);
    verifyPrefixTargets(scenario, sarif);
    const delivery = JSON.parse(fs.readFileSync(path.join(workRoot, 'stage', item.case, 'delivery.json')));
    assert.equal(delivery.code, 'CI_OK');
    assert.deepEqual(delivery.files, ['summary.md', 'source-aware.sarif', 'ci-record.json']);
  }
  fs.mkdirSync(stage, { recursive: false, mode: 0o700 });
  const staged = path.join(stage, 'safe-result.json');
  fs.writeFileSync(staged, bytes, { flag: 'wx', mode: 0o600 });
  assert.equal(fileHash(staged), hash(bytes));
  process.stdout.write(`PILOT_SAFE_STAGE_SHA256=${hash(bytes)}\n`);
}

if (require.main === module) {
  const [mode, first, second, third, fourth] = process.argv.slice(2);
  Promise.resolve().then(() => {
    if (mode === 'prepare' && first && !second) return prepareDependencies(first);
    if (mode === 'evaluate' && first && second && third && fourth) return evaluate(first, second, third, fourth);
    if (mode === 'verify' && first && second && third && fourth) return verifySafeResult(first, second, third, fourth);
    throw Error('PILOT_ARGUMENTS');
  }).catch(() => { console.error('PILOT_FAILED'); process.exitCode = 1; });
}

module.exports = { mutate, ruleCounts, checkExpectedCounts, verifyFindingTargets, verifyArchive };
