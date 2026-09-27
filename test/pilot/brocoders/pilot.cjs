#!/usr/bin/env node
// Fixed public-source evaluation. Detailed Source reports stay on the runner.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const shared = require('../realworld/pilot.cjs');
const { command, hash, fileHash, candidateIdentity, runDriver, ruleCounts, matchEach,
  sourceLocation, openApiLocation, exactKeys } = shared;
const fixture = __dirname;
const manifest = require('./source-manifest.json');
const expected = require('./expectations.json');
const passportExpected = require('./passport-expectations.json');
const cases = require('./cases.json');
const archive = path.join(fixture, 'source.tar.gz');
const preparedLock = path.join(fixture, 'prepared-package-lock.json');
const originalLockSha = manifest.fileSha256['package-lock.json'];
const preparedLockSha = '78f85d33ed84ad7214ea81e4996a2a3741c5670c9f199137b1e91dbc056919b6';
const inputNames = ['openapi-api.json', 'openapi-no-prefix.json', 'policy-api.yml',
  'policy-no-prefix.yml', 'auth-empty.json', 'cases.json', 'expectations.json',
  'passport-expectations.json'];
const operationKey = op => `${op.method} ${op.path}`;
const targetKey = (op, prefix) => `${op.method} ${prefix ? op.uriApiPrefixPath : op.uriNoPrefixPath}`;
const sorted = values => [...values].sort();

function verifyArchive() {
  assert.equal(fileHash(archive), manifest.evaluationArchiveSha256);
  const names = command('tar', ['-tzf', archive]).stdout.trimEnd().split('\n');
  assert.deepEqual(sorted(names), sorted(Object.keys(manifest.fileSha256)));
  for (const name of names) assert.ok(name && !path.isAbsolute(name)
    && !name.split('/').includes('..') && !name.includes('\\'));
  assert.equal(fileHash(preparedLock), preparedLockSha);
  assert.equal(manifest.commit, expected.sourceCommit);
  return names;
}
function verifySource(root, names) {
  for (const name of names) assert.equal(fileHash(path.join(root, name)), manifest.fileSha256[name], name);
  assert.equal(fileHash(path.join(root, 'package-lock.json')), originalLockSha);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).license, 'MIT');
  assert.match(fs.readFileSync(path.join(root, 'LICENSE'), 'utf8'), /Copyright \(c\) 2023 Brocoders/);
}
function prepare(directory) {
  verifyArchive();
  fs.mkdirSync(directory, { recursive: false, mode: 0o700 });
  for (const name of ['package.json']) {
    fs.writeFileSync(path.join(directory, name), command('tar', ['-xOzf', archive, name]).stdout,
      { flag: 'wx', mode: 0o600 });
  }
  fs.copyFileSync(preparedLock, path.join(directory, 'package-lock.json'), fs.constants.COPYFILE_EXCL);
  const started = Date.now();
  const result = cp.spawnSync('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], {
    cwd: directory, stdio: 'inherit', timeout: 300_000,
    env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: '' },
  });
  assert.equal(result.error, undefined, 'PILOT_PREP_PROCESS');
  assert.equal(result.signal, null, 'PILOT_PREP_TIMEOUT');
  assert.equal(result.status, 0, 'PILOT_PREP_EXIT');
  assert.ok(fs.statSync(path.join(directory, 'node_modules/@nestjs/common')).isDirectory());
  const proof = { originalLockSha256: originalLockSha, preparedLockSha256: preparedLockSha,
    durationMs: Date.now() - started, node: process.version, npmRc: result.status };
  fs.writeFileSync(path.join(directory, 'preparation.json'), JSON.stringify(proof) + '\n',
    { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify({ code: 'BROCODERS_DEPENDENCIES_PREPARED', ...proof }) + '\n');
}
function sourceFile(op) { return `source/${op.source}`; }
function expectedKeys(prefix) { return sorted(expected.operations.map(op => targetKey(op, prefix))); }
function assertExpectedRoutes(comparison, prefix) {
  const found = new Map(comparison.contract.operations.map(op => [op.routeKey, op]));
  assert.equal(found.size, comparison.contract.operations.length, 'PILOT_DUPLICATE_ROUTE');
  for (const op of expected.operations) {
    const route = targetKey(op, prefix);
    const analyzed = found.get(route);
    assert.ok(analyzed, `PILOT_ROUTE_MISSING ${route}`);
    assert.equal(analyzed.auth.mode, op.expectedAnalyzerAuth, `PILOT_AUTH ${route}`);
    assert.ok(analyzed.provenance.some(p => p.uri === sourceFile(op)
      && p.pointer.startsWith(`line:${op.line}:`) && p.capability === 'httpMethods'),
    `PILOT_METHOD_PROVENANCE ${route}`);
  }
  const target = new Set(expected.operations.map(op => targetKey(op, prefix)));
  const evaluationOut = [...found.keys()].filter(key => !target.has(key));
  assert.deepEqual(sorted(evaluationOut), sorted(prefix
    ? cases.observedEvaluationOut.uriApiPrefix : cases.observedEvaluationOut.uriNoPrefix),
  'PILOT_EVALUATION_OUT_ROUTES');
  assert.ok(![...found.keys()].some(key => /^\w+ \/(?:api\/)?(?:auth|users)(?:\/|$)/.test(key)),
    'PILOT_UNVERSIONED_ROUTE');
  return evaluationOut;
}
function assertPassportObservation(observation) {
  assert.ok(observation, 'PILOT_PASSPORT_OBSERVATION_MISSING');
  assert.equal(observation.observer, 'nestjs-passport-direct-factory@1');
  assert.match(observation.digest, /^sha256:[a-f0-9]{64}$/);
  const target = new Map(expected.operations.map(op => [targetKey(op, false), op]));
  const expectedSites = passportExpected.callSites.map(site => ({
    sourceUri: `source/${site.source}`, line: site.line, scope: site.scope,
    strategy: site.strategy,
    operations: sorted(site.operations.map(key => key.replace(' /api/', ' /'))),
  }));
  const byId = new Map(observation.callSites.map(site => [site.id, site]));
  assert.equal(byId.size, observation.callSites.length, 'PILOT_PASSPORT_DUPLICATE_SITE');
  const scoped = observation.associations.filter(item => target.has(`${item.method} ${item.comparisonPath}`));
  const actualBySite = new Map();
  for (const item of scoped) {
    const site = byId.get(item.callSiteId);
    assert.ok(site?.strategy, 'PILOT_PASSPORT_ASSOCIATION_SITE');
    assert.equal(site.module, '@nestjs/passport');
    assert.equal(site.export, 'AuthGuard');
    assert.equal(site.reason, undefined);
    assert.equal(item.authMode, 'unknown', 'PILOT_PASSPORT_AUTH_PROMOTED');
    const key = `${item.method} ${item.comparisonPath}`;
    assert.equal(item.localPath, target.get(key).localPath.replace(':id', '{id}'));
    const routes = actualBySite.get(site.id) ?? [];
    routes.push(key);
    actualBySite.set(site.id, routes);
  }
  const actualSites = [...actualBySite].map(([id, routes]) => {
    const site = byId.get(id);
    return { sourceUri: site.sourceUri, line: site.line, scope: site.scope,
      strategy: site.strategy, operations: sorted(routes) };
  });
  const normalize = value => JSON.stringify(value);
  assert.deepEqual(sorted(actualSites.map(normalize)), sorted(expectedSites.map(normalize)),
    'PILOT_PASSPORT_EXACT_ASSOCIATIONS');
  const operationStatuses = observation.operations.filter(item => target.has(
    `${item.method} ${item.comparisonPath}`));
  assert.deepEqual(sorted(operationStatuses.map(item => JSON.stringify({
    route: `${item.method} ${item.comparisonPath}`, status: item.status, authMode: item.authMode,
  }))), sorted(expected.operations.map(op => JSON.stringify({
    route: targetKey(op, false), status: op.guardSyntax ? 'observed' : 'no-direct-factory',
    authMode: 'unknown',
  }))), 'PILOT_PASSPORT_OPERATION_STATUS');
  assert.equal(scoped.length, passportExpected.expected.operationAssociations);
  assert.equal(actualSites.length, passportExpected.expected.callSites);
  const counts = Object.fromEntries(Object.keys(passportExpected.expected.strategyAssociations).map(strategy => (
    [strategy, scoped.filter(item => byId.get(item.callSiteId).strategy === strategy).length]
  )));
  assert.deepEqual(counts, passportExpected.expected.strategyAssociations);
  const noDirect = operationStatuses.filter(item => item.status === 'no-direct-factory').length;
  assert.equal(noDirect, passportExpected.withoutDirectFactory.length);
  return { summary: { observer: observation.observer, digest: observation.digest,
    callSites: actualSites.length, operationAssociations: scoped.length,
    strategyAssociations: counts, noDirectOperations: noDirect,
    authUnknown: operationStatuses.filter(item => item.authMode === 'unknown').length },
  evidence: observation };
}
async function inspect(installed, workspace) {
  const { runNestJsSourceAnalysisInternal } = require(path.join(installed, 'source/nestjs/analyzer.js'));
  const { DEFAULT_SOURCE_ANALYSIS_LIMITS } = require(path.join(installed, 'source-analysis/index.js'));
  const context = { workspaceRoot: workspace, entrypoints: ['source/tsconfig.build.json'],
    limits: DEFAULT_SOURCE_ANALYSIS_LIMITS, logger: { log() {} } };
  const started = Date.now();
  const noUri = await runNestJsSourceAnalysisInternal(context);
  assert.equal(noUri.execution.status, 'success', 'PILOT_NO_URI_ANALYSIS');
  const noUriResult = noUri.execution.result;
  const plain = new Set(noUriResult.contract.operations.map(op => op.routeKey));
  assert.ok(plain.has('GET /'));
  for (const op of expected.operations) {
    assert.ok(!plain.has(`${op.method} ${op.localPath}`), 'PILOT_VERSION_LOST');
    assert.ok(noUriResult.unresolvedOperations.some(item => item.sourceUri === sourceFile(op)
      && item.methods.includes(op.method)), 'PILOT_VERSION_UNRESOLVED_MISSING');
  }
  const noUriMs = Date.now() - started;
  const uriStarted = Date.now();
  const uri = await runNestJsSourceAnalysisInternal(context, undefined, undefined, undefined, 'uri');
  assert.equal(uri.execution.status, 'success', 'PILOT_URI_ANALYSIS');
  assert.ok(uri.uriComparison, 'PILOT_URI_METADATA_MISSING');
  const comparison = uri.uriComparison;
  const out = assertExpectedRoutes(comparison, false);
  const passport = assertPassportObservation(uri.passportFactoryObservation);
  for (const op of expected.operations) {
    const matched = comparison.routes.filter(route => route.status === 'resolved'
      && route.method === op.method && route.sourceUri === sourceFile(op)
      && route.comparisonPath === op.uriNoPrefixPath);
    assert.equal(matched.length, 1, `PILOT_VERSION_METADATA ${targetKey(op, false)}`);
    assert.equal(matched[0].version, op.effectiveVersion);
    assert.equal(matched[0].origin, 'controller');
    assert.equal(matched[0].localPath, op.localPath.replace(':id', '{id}'));
    assert.equal(matched[0].line, Number(op.versionOrigin.split(':').pop()));
  }
  const { prefixSourceContract } = require(path.join(installed, 'contract/source-global-prefix.js'));
  const prefixed = { contract: prefixSourceContract(comparison.contract, '/api') };
  const prefixedOut = assertExpectedRoutes(prefixed, true);
  assert.equal(comparison.unresolvedOperations.length, 1);
  assert.equal(comparison.unresolvedOperations[0].sourceUri, 'source/src/home/home.controller.ts');
  const diagnosticCodes = sorted([...new Set(comparison.diagnostics.map(d => d.code))]);
  assert.deepEqual(diagnosticCodes,
    ['SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA', 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED']);
  const routeEvidence = { noUriKeys: sorted(plain),
    noUriUnresolved: noUriResult.unresolvedOperations.map(item => ({
      sourceUri: item.sourceUri, methods: item.methods, reason: item.reason })),
    uriKeys: sorted(comparison.contract.operations.map(op => op.routeKey)),
    uriRoutes: comparison.routes.map(route => ({ status: route.status,
      sourceUri: route.sourceUri, method: route.method, localPath: route.localPath,
      version: route.version, origin: route.origin, comparisonPath: route.comparisonPath })),
    prefixedKeys: sorted(prefixed.contract.operations.map(op => op.routeKey)),
    targetAuthUnknown: sorted(comparison.contract.operations.filter(op =>
      expectedKeys(false).includes(op.routeKey) && op.auth.mode === 'unknown').map(op => op.routeKey)),
    evaluationOut: out, passport: passport.evidence,
    uriUnresolved: comparison.unresolvedOperations.map(item => ({
      sourceUri: item.sourceUri, reason: item.reason })) };
  return { summary: { noUriMs, uriMs: Date.now() - uriStarted,
    metrics: uri.execution.result.metrics, noUriResolved: plain.size,
    noUriUnresolved: noUriResult.unresolvedOperations.length,
    scored: expected.operations.length, uriResolved: comparison.contract.operations.length,
    evaluationOut: out, prefixedEvaluationOut: prefixedOut,
    uriUnresolved: comparison.unresolvedOperations.length,
    authUnknown: expected.operations.length, diagnosticCodes, rssBytes: process.memoryUsage().rss },
  routeEvidence, passport: passport.summary };
}
function mutate(change, openapi, policy) {
  const pathKey = '/api/v1/auth/me';
  if (change === 'wrong-version') {
    openapi.paths['/api/v2/auth/me'] = { get: openapi.paths[pathKey].get };
    delete openapi.paths[pathKey].get;
    if (Object.keys(openapi.paths[pathKey]).length === 0) delete openapi.paths[pathKey];
  } else if (change === 'method-mismatch') {
    openapi.paths[pathKey].put = openapi.paths[pathKey].get;
    delete openapi.paths[pathKey].get;
  } else if (change === 'source-only') {
    delete openapi.paths['/api/v1/auth/email/login'];
  } else if (change === 'declared-only') {
    openapi.paths['/api/v1/evaluation-only'] = { get: { responses: { '200': {
      description: 'Independent evaluation-only declaration' } } } };
  } else if (change === 'policy-method') {
    policy = policy.replace('GET, POST, PUT, PATCH, DELETE', 'GET, POST, PUT, PATCH');
  } else if (change === 'policy-route') {
    policy = policy.replace('response_headers: {}', `  - name: evaluation-only-policy-route
    match:
      path_prefixes: ["/api/v1/evaluation-only-policy"]
    auth_gate:
      type: signed_url
      exact_path: true
      secret_env: CSF_EVALUATION_ONLY_SECRET
response_headers: {}`);
  } else if (change === 'declared-auth') {
    openapi.components = { securitySchemes: { BearerAuth: { type: 'http', scheme: 'bearer' } } };
    openapi.paths[pathKey].get.security = [{ BearerAuth: [] }];
  } else assert.equal(change, 'none', 'PILOT_UNKNOWN_MUTATION');
  return { openapi, policy };
}
function findingsFor(report) {
  assert.equal(report.version, '2.1.0');
  return report.runs[0].results || [];
}
function assertFindingTarget(scenario, report) {
  if (!scenario.expectRule) return 0;
  const targets = findingsFor(report).filter(item => item.ruleId === scenario.expectRule);
  const target = scenario.target;
  if (scenario.change === 'method-mismatch') {
    const op = expected.operations.find(op => op.method === target.sourceMethod
      && op.uriApiPrefixPath === target.path);
    assert.ok(op);
    matchEach(targets, [op], item => sourceLocation(item, op)
      && openApiLocation(item, scenario.name, target.declaredMethod, target.path));
  } else if (scenario.change === 'declared-only' || scenario.change === 'declared-auth') {
    matchEach(targets, [target], (item, entry) =>
      openApiLocation(item, scenario.name, entry.method, entry.path));
  } else if (scenario.change === 'source-only') {
    const op = expected.operations.find(op => op.method === target.method
      && op.uriApiPrefixPath === target.path);
    assert.ok(op, 'PILOT_SOURCE_ONLY_TARGET');
    const all = [...cases.observedEvaluationOut.uriApiPrefix, `${target.method} ${target.path}`];
    matchEach(targets, all, (item, key) => {
      const route = item.properties?.sourceAware?.route;
      return `${route?.method} ${route?.path}` === key
        && (key !== `${target.method} ${target.path}` || sourceLocation(item, op));
    });
  } else if (scenario.change === 'policy-method') {
    matchEach(targets, target.paths, (item, route) =>
      item.properties?.sourceAware?.route?.method === target.method
      && item.properties?.sourceAware?.route?.path === route);
  } else if (scenario.change === 'policy-route') {
    matchEach(targets, [target], item => [...(item.locations || []), ...(item.relatedLocations || [])]
      .some(location => location.physicalLocation?.artifactLocation?.uri
        === `evaluation/${scenario.name}/policy.yml`
        && location.logicalLocations?.some(logical =>
          logical.fullyQualifiedName === '/routes/1/match/path_prefixes')));
  }
  return scenario.change === 'policy-method' ? target.paths.length : 1;
}
function copyInputs(destination) {
  const hashes = {};
  for (const name of inputNames) {
    const bytes = fs.readFileSync(path.join(fixture, name));
    fs.writeFileSync(path.join(destination, name), bytes, { flag: 'wx', mode: 0o600 });
    hashes[name] = hash(bytes);
  }
  return hashes;
}
function runCliFormats(installed, workspace) {
  const cli = path.join(installed, 'bin/cli.js');
  const args = ['contract', 'source-diff', '--workspace-root', workspace,
    '--openapi', 'evaluation/openapi-api.json', '--policy', 'evaluation/policy-api.yml',
    '--source', 'source/tsconfig.build.json', '--source-auth-config', 'evaluation/auth-empty.json',
    '--source-versioning', 'uri', '--source-global-prefix', '/api', '--target', 'aws',
    '--current-date', '2026-09-27', '--fail-on', 'never'];
  const { hasUnsafeSensitiveText } = require(path.join(installed, 'contract/sensitive-text.js'));
  const formats = {};
  for (const format of ['text', 'json', 'sarif', 'summary']) {
    const result = command(process.execPath, [cli, ...args, '--format', format], { cwd: workspace });
    assert.equal(hasUnsafeSensitiveText(result.stdout), false, 'PILOT_CLI_PRIVACY');
    if (format === 'json' || format === 'sarif') JSON.parse(result.stdout);
    formats[format] = { sha256: hash(result.stdout), durationMs: result.durationMs };
  }
  const out = 'evaluation/r07-output.json';
  command(process.execPath, [cli, ...args, '--format', 'json', '--out', out], { cwd: workspace });
  const saved = fs.readFileSync(path.join(workspace, out));
  assert.equal(hasUnsafeSensitiveText(saved.toString('utf8')), false, 'PILOT_SAVED_PRIVACY');
  JSON.parse(saved.toString('utf8'));
  assert.equal(hash(saved), formats.json.sha256, 'PILOT_OUT_CHANGED_REPORT');
  return { formats, outSha256: hash(saved) };
}
async function evaluate(candidate, dependencies, workRoot, output) {
  const { metadata, installed } = candidateIdentity(candidate);
  assert.equal(fs.realpathSync(path.join(candidate, 'consumer/node_modules/.bin/cdn-security')),
    path.join(installed, 'bin/cli.js'), 'PILOT_BINARY_NOT_INSTALLED');
  verifyArchive();
  assert.equal(fileHash(path.join(dependencies, 'package-lock.json')), preparedLockSha);
  const preparation = JSON.parse(fs.readFileSync(path.join(dependencies, 'preparation.json')));
  fs.mkdirSync(workRoot, { recursive: false, mode: 0o700 });
  const workspace = path.join(workRoot, 'workspace');
  const source = path.join(workspace, 'source');
  fs.mkdirSync(workspace, { mode: 0o700 });
  fs.mkdirSync(source, { mode: 0o700 });
  command('tar', ['-xzf', archive, '-C', source]);
  const names = verifyArchive();
  verifySource(source, names);
  fs.cpSync(path.join(dependencies, 'node_modules'), path.join(source, 'node_modules'), { recursive: true });
  const evaluation = path.join(workspace, 'evaluation');
  fs.mkdirSync(evaluation, { mode: 0o700 });
  const inputHashes = copyInputs(evaluation);
  const { summary: operations, routeEvidence, passport } = await inspect(installed, workspace);
  const routeEvidenceFile = path.join(workRoot, 'route-evidence.json');
  fs.writeFileSync(routeEvidenceFile, JSON.stringify(routeEvidence) + '\n', { flag: 'wx', mode: 0o600 });
  const { hasUnsafeSensitiveText } = require(path.join(installed, 'contract/sensitive-text.js'));
  const caseResults = [];
  let controlledFindingTP = 0;
  for (const scenario of cases.cases) {
    const dir = path.join(evaluation, scenario.name);
    fs.mkdirSync(dir, { mode: 0o700 });
    let openapi = JSON.parse(fs.readFileSync(path.join(evaluation, `openapi-${scenario.contract}.json`)));
    let policy = fs.readFileSync(path.join(evaluation, `policy-${scenario.contract}.yml`), 'utf8');
    ({ openapi, policy } = mutate(scenario.change, openapi, policy));
    fs.writeFileSync(path.join(dir, 'openapi.json'), JSON.stringify(openapi) + '\n', { flag: 'wx' });
    fs.writeFileSync(path.join(dir, 'policy.yml'), policy, { flag: 'wx' });
    fs.copyFileSync(path.join(evaluation, 'auth-empty.json'), path.join(dir, 'auth.json'), fs.constants.COPYFILE_EXCL);
    const config = { workspaceRoot: workspace, openapi: `evaluation/${scenario.name}/openapi.json`,
      policy: `evaluation/${scenario.name}/policy.yml`, target: 'aws', source: 'source/tsconfig.build.json',
      sourceAuthConfig: `evaluation/${scenario.name}/auth.json`,
      ...(scenario.sourceVersioning ? { sourceVersioning: scenario.sourceVersioning } : {}),
      ...(scenario.prefix ? { sourceGlobalPrefix: scenario.prefix } : {}),
      currentDate: '2026-09-27', failOn: 'never', format: 'summary' };
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(config) + '\n', { flag: 'wx' });
    const reports = path.join(workspace, 'reports', scenario.name);
    fs.mkdirSync(reports, { recursive: true, mode: 0o700 });
    const stage = path.join(workRoot, 'stage', scenario.name);
    fs.mkdirSync(stage, { recursive: true, mode: 0o700 });
    const env = { ...process.env, NODE_PATH: '', NODE_OPTIONS: '',
      GITHUB_STEP_SUMMARY: path.join(dir, 'step-summary.md'), GITHUB_OUTPUT: path.join(dir, 'step-output.txt'),
      CSF_PRODUCER_STATE: 'success', CSF_ACCEPTANCE_STATE: 'success',
      CSF_ANALYZE_OUTCOME: 'success', CSF_PUBLISH_OUTCOME: 'success',
      CSF_STAGE_OUTCOME: 'success', CSF_ARTIFACT_OUTCOME: 'success' };
    const run = runDriver(installed, 'run', [path.join(dir, 'config.json'), candidate, reports], env);
    assert.match(run.stdout, /^CI_ANALYSIS_RECORDED exit=0\n$/);
    const recordPath = path.join(reports, 'ci-record.json');
    const record = JSON.parse(fs.readFileSync(recordPath));
    assert.equal(record.analysis.exitCode, 0);
    assert.equal(record.analysis.status, 'partial');
    assert.equal(record.candidate.sha256, metadata.sha256);
    assert.equal(record.routingAssumption?.sourceVersioning, scenario.sourceVersioning ?? undefined);
    assert.equal(record.routingAssumption?.globalPrefix, scenario.prefix ?? undefined);
    runDriver(installed, 'publish', [recordPath, candidate, stage], env);
    runDriver(installed, 'verify-stage', [recordPath, candidate, path.join(stage, 'delivery.json')], env);
    const gate = runDriver(installed, 'gate', [recordPath, candidate, path.join(stage, 'delivery.json')], env);
    assert.match(gate.stdout, /^CI_SOURCE_AWARE_GATE_PASS\n$/);
    const delivery = JSON.parse(fs.readFileSync(path.join(stage, 'delivery.json')));
    assert.equal(delivery.code, 'CI_OK');
    assert.equal(delivery.summaryTransfer, 'success');
    assert.equal(delivery.artifactListVerified, true);
    const summary = fs.readFileSync(path.join(reports, 'summary.md'), 'utf8');
    const sarifText = fs.readFileSync(path.join(reports, 'source-aware.sarif'), 'utf8');
    assert.equal(hasUnsafeSensitiveText(summary), false, 'PILOT_SUMMARY_PRIVACY');
    assert.equal(hasUnsafeSensitiveText(sarifText), false, 'PILOT_SARIF_PRIVACY');
    assert.equal(fs.readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8'), summary);
    const report = JSON.parse(sarifText);
    const controlledTargets = assertFindingTarget(scenario, report);
    controlledFindingTP += controlledTargets;
    const counts = ruleCounts(report);
    const controlledCounts = {
      'R05-method': 1, 'R05-source-only': 6, 'R05-declared-only': 1,
      'R05-policy-method': 2, 'R05-policy-route': 1, 'R06-declared-auth': 1,
    };
    if (Object.hasOwn(controlledCounts, scenario.name)) {
      assert.equal(counts[scenario.expectRule], controlledCounts[scenario.name],
        `PILOT_CONTROLLED_FINDING_COUNT ${scenario.name}`);
    }
    if (scenario.name === 'R03-uri-api') {
      assert.equal(counts['SC-INVENTORY-001'], 5);
      assert.equal(counts['SC-AUTHN-004'], 16);
    }
    if (scenario.name === 'R04-omitted-prefix' || scenario.name === 'R04-wrong-prefix') {
      assert.equal(counts['SC-INVENTORY-003'], 16, 'PILOT_NO_PREFIX_AUTOCORRECTION');
    }
    if (scenario.name === 'R04-wrong-version') {
      assert.ok(findingsFor(report).some(item => item.ruleId === 'SC-INVENTORY-003'
        && openApiLocation(item, scenario.name, scenario.target.method, scenario.target.declaredPath)),
      'PILOT_WRONG_VERSION_DECLARED');
    }
    caseResults.push({ case: scenario.name, group: scenario.group, analysisStatus: record.analysis.status,
      ciDelivery: delivery.code, findings: counts, targetVerified: true, controlledTargets,
      durationMs: run.durationMs, summarySha256: hash(summary), sarifSha256: hash(sarifText),
      openapiSha256: fileHash(path.join(dir, 'openapi.json')),
      policySha256: fileHash(path.join(dir, 'policy.yml')),
      configSha256: fileHash(path.join(dir, 'config.json')) });
  }
  const r07 = runCliFormats(installed, workspace);
  verifySource(source, names);
  for (const [name, digest] of Object.entries(inputHashes)) {
    assert.equal(fileHash(path.join(evaluation, name)), digest, 'PILOT_INPUT_MUTATED');
  }
  const safe = { schemaVersion: 1, code: 'PILOT_PASS', source: { repository: manifest.repository,
    commit: manifest.commit, tree: manifest.tree, archiveSha256: manifest.evaluationArchiveSha256,
    fileCount: manifest.adoptedFileCount },
  candidate: { source: metadata.source, harness: metadata.harness, tree: metadata.tree,
    run: metadata.run, attempt: metadata.attempt, tgzSha256: metadata.sha256,
    lockSha256: metadata.lockSha256 }, targetDependencies: preparation,
  inputHashes, operations, passport, routeEvidenceSha256: fileHash(routeEvidenceFile),
  cases: caseResults, R07: r07,
  score: { exactRouteTP: 16, exactRouteFP: 0, exactRouteFN: 0,
    unit: cases.denominator.routeTruePositiveUnit, denominator: 16,
    evaluationOut: operations.evaluationOut.length, authUnknown: operations.authUnknown,
    unresolved: operations.uriUnresolved, inputErrors: 0, resourceErrors: 0, internalErrors: 0,
    applications: 1, controlledFindingTP, controlledFindingFP: 0, controlledFindingFN: 0,
    controlledFindingUnit: cases.denominator.findingTruePositiveUnit,
    mutationCases: caseResults.filter(item => item.group === 'R04' || item.group === 'R05').length } };
  assert.equal(hasUnsafeSensitiveText(JSON.stringify(safe)), false, 'PILOT_SAFE_PRIVACY');
  const bytes = Buffer.from(JSON.stringify(safe, null, 2) + '\n');
  assert.ok(bytes.length <= 65_536, 'PILOT_SAFE_SIZE');
  fs.writeFileSync(output, bytes, { flag: 'wx', mode: 0o600 });
  process.stdout.write('BROCODERS_PILOT_PASS\n');
}
function verify(candidate, workRoot, output, stage) {
  const { metadata, installed } = candidateIdentity(candidate);
  assert.equal(fs.realpathSync(path.join(candidate, 'consumer/node_modules/.bin/cdn-security')),
    path.join(installed, 'bin/cli.js'));
  const bytes = fs.readFileSync(output);
  assert.ok(bytes.length > 0 && bytes.length <= 65_536);
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  const { hasUnsafeSensitiveText } = require(path.join(installed, 'contract/sensitive-text.js'));
  assert.equal(hasUnsafeSensitiveText(bytes.toString('utf8')), false);
  const digest = value => assert.match(value, /^[a-f0-9]{64}$/);
  const finite = value => assert.ok(Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000_000_000);
  exactKeys(value, ['schemaVersion', 'code', 'source', 'candidate', 'targetDependencies',
    'inputHashes', 'operations', 'passport', 'routeEvidenceSha256', 'cases', 'R07', 'score']);
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.code, 'PILOT_PASS');
  exactKeys(value.source, ['repository', 'commit', 'tree', 'archiveSha256', 'fileCount']);
  assert.deepEqual(value.source, { repository: manifest.repository, commit: manifest.commit,
    tree: manifest.tree, archiveSha256: manifest.evaluationArchiveSha256,
    fileCount: manifest.adoptedFileCount });
  exactKeys(value.candidate, ['source', 'harness', 'tree', 'run', 'attempt', 'tgzSha256', 'lockSha256']);
  assert.deepEqual(value.candidate, { source: metadata.source, harness: metadata.harness,
    tree: metadata.tree, run: metadata.run, attempt: metadata.attempt,
    tgzSha256: metadata.sha256, lockSha256: metadata.lockSha256 });
  exactKeys(value.targetDependencies, ['originalLockSha256', 'preparedLockSha256',
    'durationMs', 'node', 'npmRc']);
  assert.equal(value.targetDependencies.originalLockSha256, originalLockSha);
  assert.equal(value.targetDependencies.preparedLockSha256, preparedLockSha);
  finite(value.targetDependencies.durationMs);
  assert.match(value.targetDependencies.node, /^v\d+\.\d+\.\d+$/);
  assert.equal(value.targetDependencies.npmRc, 0);
  exactKeys(value.operations, ['noUriMs', 'uriMs', 'metrics', 'noUriResolved',
    'noUriUnresolved', 'scored', 'uriResolved', 'evaluationOut', 'prefixedEvaluationOut',
    'uriUnresolved', 'authUnknown', 'diagnosticCodes', 'rssBytes']);
  exactKeys(value.operations.metrics, ['files', 'totalSourceBytes', 'largestFileBytes',
    'astNodes', 'diagnostics', 'operations', 'maxDepth']);
  for (const metric of Object.values(value.operations.metrics)) finite(metric);
  for (const field of ['noUriMs', 'uriMs', 'noUriResolved', 'noUriUnresolved',
    'scored', 'uriResolved', 'uriUnresolved', 'authUnknown', 'rssBytes']) finite(value.operations[field]);
  assert.equal(value.operations.noUriResolved, 1);
  assert.equal(value.operations.scored, expected.operations.length);
  assert.equal(value.operations.uriResolved, expected.operations.length
    + cases.observedEvaluationOut.uriNoPrefix.length);
  assert.equal(value.operations.authUnknown, expected.operations.length);
  assert.equal(value.operations.uriUnresolved, 1);
  assert.deepEqual(sorted(value.operations.evaluationOut), sorted(cases.observedEvaluationOut.uriNoPrefix));
  assert.deepEqual(sorted(value.operations.prefixedEvaluationOut), sorted(cases.observedEvaluationOut.uriApiPrefix));
  assert.deepEqual(value.operations.diagnosticCodes,
    ['SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA', 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED']);
  digest(value.routeEvidenceSha256);
  const routeEvidenceFile = path.join(workRoot, 'route-evidence.json');
  assert.equal(fileHash(routeEvidenceFile), value.routeEvidenceSha256, 'PILOT_ROUTE_EVIDENCE_HASH');
  const proof = JSON.parse(fs.readFileSync(routeEvidenceFile, 'utf8'));
  assert.deepEqual(assertPassportObservation(proof.passport).summary, value.passport,
    'PILOT_PASSPORT_SAFE_RESULT');
  assert.equal(value.passport.authUnknown, passportExpected.expected.sourceAuthUnknown);
  assert.deepEqual(proof.noUriKeys, ['GET /']);
  assert.deepEqual(proof.targetAuthUnknown, expectedKeys(false));
  for (const prefix of [false, true]) {
    const keys = prefix ? proof.prefixedKeys : proof.uriKeys;
    assert.deepEqual(keys, sorted([...expectedKeys(prefix), ...(prefix
      ? cases.observedEvaluationOut.uriApiPrefix : cases.observedEvaluationOut.uriNoPrefix)]),
    'PILOT_FULL_ROUTE_PROOF');
  }
  for (const op of expected.operations) assert.ok(proof.uriRoutes.some(route =>
    route.status === 'resolved' && route.sourceUri === sourceFile(op)
      && route.method === op.method && route.comparisonPath === op.uriNoPrefixPath
      && route.version === op.effectiveVersion && route.origin === 'controller'),
  `PILOT_VERSION_PROOF ${targetKey(op, false)}`);
  assert.deepEqual(proof.evaluationOut, value.operations.evaluationOut);
  assert.equal(proof.uriUnresolved.length, value.operations.uriUnresolved);
  assert.deepEqual(value.inputHashes, Object.fromEntries(inputNames.map(name =>
    [name, fileHash(path.join(fixture, name))])));
  exactKeys(value.R07, ['formats', 'outSha256']);
  exactKeys(value.R07.formats, ['text', 'json', 'sarif', 'summary']);
  for (const format of Object.values(value.R07.formats)) {
    exactKeys(format, ['sha256', 'durationMs']);
    digest(format.sha256);
    finite(format.durationMs);
  }
  assert.equal(value.R07.outSha256, value.R07.formats.json.sha256);
  assert.deepEqual(value.cases.map(item => item.case), cases.cases.map(item => item.name));
  let controlledTargets = 0;
  for (const item of value.cases) {
    exactKeys(item, ['case', 'group', 'analysisStatus', 'ciDelivery', 'findings',
      'targetVerified', 'controlledTargets', 'durationMs', 'summarySha256',
      'sarifSha256', 'openapiSha256', 'policySha256', 'configSha256']);
    const scenario = cases.cases.find(entry => entry.name === item.case);
    assert.equal(item.group, scenario.group);
    assert.equal(item.analysisStatus, 'partial');
    finite(item.durationMs);
    for (const field of ['summarySha256', 'sarifSha256', 'openapiSha256',
      'policySha256', 'configSha256']) digest(item[field]);
    assert.ok(item.findings && typeof item.findings === 'object' && !Array.isArray(item.findings));
    for (const [rule, count] of Object.entries(item.findings)) {
      assert.match(rule, /^SC-[A-Z]+-\d{3}$/);
      finite(count);
    }
    const reports = path.join(workRoot, 'workspace/reports', item.case);
    assert.equal(fileHash(path.join(reports, 'summary.md')), item.summarySha256);
    assert.equal(fileHash(path.join(reports, 'source-aware.sarif')), item.sarifSha256);
    const report = JSON.parse(fs.readFileSync(path.join(reports, 'source-aware.sarif')));
    assert.deepEqual(item.findings, ruleCounts(report));
    assert.equal(item.controlledTargets, assertFindingTarget(scenario, report));
    controlledTargets += item.controlledTargets;
    assert.equal(item.ciDelivery, 'CI_OK');
    assert.equal(item.targetVerified, true);
  }
  exactKeys(value.score, ['exactRouteTP', 'exactRouteFP', 'exactRouteFN', 'unit',
    'denominator', 'evaluationOut', 'authUnknown', 'unresolved', 'inputErrors',
    'resourceErrors', 'internalErrors', 'applications', 'controlledFindingTP',
    'controlledFindingFP', 'controlledFindingFN', 'controlledFindingUnit', 'mutationCases']);
  assert.deepEqual(value.score, { exactRouteTP: expected.operations.length,
    exactRouteFP: 0, exactRouteFN: 0, unit: cases.denominator.routeTruePositiveUnit,
    denominator: cases.denominator.scoredSourceOperations,
    evaluationOut: value.operations.evaluationOut.length,
    authUnknown: value.operations.authUnknown, unresolved: value.operations.uriUnresolved,
    inputErrors: 0, resourceErrors: 0, internalErrors: 0,
    applications: cases.denominator.independentRealApplications,
    controlledFindingTP: controlledTargets, controlledFindingFP: 0,
    controlledFindingFN: 0, controlledFindingUnit: cases.denominator.findingTruePositiveUnit,
    mutationCases: cases.cases.filter(item => item.group === 'R04' || item.group === 'R05').length });
  assert.equal(controlledTargets, 7);
  fs.mkdirSync(stage, { recursive: false, mode: 0o700 });
  fs.writeFileSync(path.join(stage, 'safe-result.json'), bytes, { flag: 'wx', mode: 0o600 });
  assert.equal(fileHash(path.join(stage, 'safe-result.json')), hash(bytes));
  process.stdout.write(`BROCODERS_SAFE_STAGE_SHA256=${hash(bytes)}\n`);
}
if (require.main === module) {
  const [mode, first, second, third, fourth] = process.argv.slice(2);
  Promise.resolve().then(() => {
    if (mode === 'prepare' && first && !second) return prepare(first);
    if (mode === 'evaluate' && first && second && third && fourth) return evaluate(first, second, third, fourth);
    if (mode === 'verify' && first && second && third && fourth) return verify(first, second, third, fourth);
    throw Error('BROCODERS_PILOT_ARGUMENTS');
  }).catch(() => { console.error('BROCODERS_PILOT_FAILED'); process.exitCode = 1; });
}
module.exports = { verifyArchive, mutate, assertExpectedRoutes, assertFindingTarget,
  assertPassportObservation };
