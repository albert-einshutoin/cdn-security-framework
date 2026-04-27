/**
 * cli-doctor.js
 *
 * Implements `cdn-security doctor` — environment diagnostics.
 *
 * Exported as `runDoctor(opts)` so bin/cli.js and doctor-unit-tests.js share
 * one path. `runDoctor` never calls process.exit — it returns an exit code
 * and the structured result, so tests can introspect individual check rows
 * without spawning a subprocess.
 *
 * Contract:
 *   input:  { cwd, pkgRoot, policyPath?, reportPath? }
 *   output: { exitCode, report }
 *   report: { generatedAt, cdnSecurityVersion, checks: [{ name, status, detail }] }
 *
 *   status ∈ { pass, fail, warn, skip }
 *   exitCode = 0 when no check has status === 'fail', else 1.
 */

const fs = require('fs');
const path = require('path');

const CHECK_NODE_VERSION = 'node_version';
const CHECK_POLICY_EXISTS = 'policy_exists';
const CHECK_POLICY_PARSES = 'policy_parses';
const CHECK_POLICY_SCHEMA_VERSION = 'policy_schema_version';
const CHECK_ENV_VARS = 'env_vars_referenced_by_policy';
const CHECK_DIST_WRITABLE = 'dist_edge_writable';
const CHECK_DEPENDENCIES = 'npm_dependencies';

const MIN_NODE_VERSION = '20.12.0';
const MIN_NODE_MAJOR = Number(MIN_NODE_VERSION.split('.')[0]);
const SCHEMA_CURRENT_VERSION = 1;

function pass(name, detail, extras = undefined) {
  return Object.assign({ name, status: 'pass', detail }, extras || {});
}
function fail(name, detail, extras = undefined) {
  return Object.assign({ name, status: 'fail', detail }, extras || {});
}
function warn(name, detail, extras = undefined) {
  return Object.assign({ name, status: 'warn', detail }, extras || {});
}
function skip(name, detail, extras = undefined) {
  return Object.assign({ name, status: 'skip', detail }, extras || {});
}

function checkNodeVersion(nodeVersion) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(nodeVersion);
  if (!match) {
    return fail(CHECK_NODE_VERSION, `Could not parse Node version: ${nodeVersion}`);
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  const [minMajor, minMinor, minPatch] = MIN_NODE_VERSION.split('.').map(Number);
  const isBelowMinimum =
    major < minMajor ||
    (major === minMajor && minor < minMinor) ||
    (major === minMajor && minor === minMinor && patch < minPatch);
  if (isBelowMinimum) {
    return fail(
      CHECK_NODE_VERSION,
      `Node ${nodeVersion} is below the required >= ${MIN_NODE_VERSION}. Upgrade before running build/deploy.`,
      { found: nodeVersion, required: `>=${MIN_NODE_VERSION}` }
    );
  }
  return pass(CHECK_NODE_VERSION, `Node ${nodeVersion} (>= ${MIN_NODE_VERSION})`, {
    found: nodeVersion,
    required: `>=${MIN_NODE_VERSION}`,
  });
}

function resolvePolicyPath(cwd, explicitPath) {
  if (explicitPath) {
    return path.isAbsolute(explicitPath) ? explicitPath : path.join(cwd, explicitPath);
  }
  const security = path.join(cwd, 'policy', 'security.yml');
  const base = path.join(cwd, 'policy', 'base.yml');
  if (fs.existsSync(security)) return security;
  if (fs.existsSync(base)) return base;
  return security; // will be reported as missing
}

function checkPolicyExists(policyPath) {
  if (!fs.existsSync(policyPath)) {
    return fail(
      CHECK_POLICY_EXISTS,
      `Policy file not found at ${policyPath}. Run \`npx cdn-security init\` to scaffold one.`,
      { policyPath }
    );
  }
  return pass(CHECK_POLICY_EXISTS, `Found ${policyPath}`, { policyPath });
}

function tryParsePolicy(policyPath) {
  try {
    const yaml = require('js-yaml');
    const raw = fs.readFileSync(policyPath, 'utf8');
    const doc = yaml.load(raw);
    return { ok: true, doc };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

function checkPolicyParses(parseResult) {
  if (!parseResult.ok) {
    return fail(CHECK_POLICY_PARSES, `YAML parse failed: ${parseResult.error}`);
  }
  if (!parseResult.doc || typeof parseResult.doc !== 'object') {
    return fail(CHECK_POLICY_PARSES, 'Policy parsed to a non-object value (must be a YAML mapping).');
  }
  return pass(CHECK_POLICY_PARSES, 'Policy parses as a YAML mapping.');
}

function checkSchemaVersion(policyDoc) {
  if (!policyDoc || typeof policyDoc !== 'object') {
    return skip(CHECK_POLICY_SCHEMA_VERSION, 'Policy did not parse; skipping schema version check.');
  }
  const version = policyDoc.version;
  if (version === undefined) {
    return fail(
      CHECK_POLICY_SCHEMA_VERSION,
      'Policy has no `version` field. Add `version: 1`.'
    );
  }
  if (version !== SCHEMA_CURRENT_VERSION) {
    return fail(
      CHECK_POLICY_SCHEMA_VERSION,
      `Policy declares version ${version} but this CLI ships schema v${SCHEMA_CURRENT_VERSION}. Run \`cdn-security migrate\` or upgrade the CLI.`,
      { found: version, expected: SCHEMA_CURRENT_VERSION }
    );
  }
  return pass(CHECK_POLICY_SCHEMA_VERSION, `Policy schema version ${version} matches CLI.`, {
    found: version,
    expected: SCHEMA_CURRENT_VERSION,
  });
}

/**
 * Walk a parsed policy and return every env var name it references. We read
 * these off the schema-bearing fields rather than string-grepping the YAML so
 * `doctor` never picks up commented-out placeholders.
 */
function collectReferencedEnvVars(policyDoc) {
  if (!policyDoc || typeof policyDoc !== 'object') return [];
  const seen = new Set();

  const routes = Array.isArray(policyDoc.routes) ? policyDoc.routes : [];
  for (const route of routes) {
    const gate = route && route.auth_gate;
    if (!gate) continue;
    if (typeof gate.token_env === 'string' && gate.token_env.length > 0) seen.add(gate.token_env);
    if (typeof gate.credentials_env === 'string' && gate.credentials_env.length > 0) seen.add(gate.credentials_env);
    if (typeof gate.secret_env === 'string' && gate.secret_env.length > 0) seen.add(gate.secret_env);
  }

  const originAuth = policyDoc.origin && policyDoc.origin.auth;
  if (originAuth && typeof originAuth.secret_env === 'string' && originAuth.secret_env.length > 0) {
    seen.add(originAuth.secret_env);
  }

  return Array.from(seen).sort();
}

function checkEnvVars(policyDoc, envProvider) {
  if (!policyDoc || typeof policyDoc !== 'object') {
    return skip(CHECK_ENV_VARS, 'Policy did not parse; skipping env var check.');
  }
  const referenced = collectReferencedEnvVars(policyDoc);
  if (referenced.length === 0) {
    return pass(CHECK_ENV_VARS, 'Policy references no build-time env vars.');
  }
  const missing = referenced.filter((name) => {
    const val = envProvider(name);
    return val === undefined || val === null || val === '';
  });
  if (missing.length > 0) {
    return fail(
      CHECK_ENV_VARS,
      `Policy references env vars that are not set: ${missing.join(', ')}. CloudFront Functions cannot read env at runtime, so these are baked into the build artifact.`,
      { referenced, missing }
    );
  }
  return pass(
    CHECK_ENV_VARS,
    `All ${referenced.length} referenced env var(s) set: ${referenced.join(', ')}.`,
    { referenced, missing: [] }
  );
}

function checkDistWritable(cwd) {
  const distDir = path.join(cwd, 'dist');
  const edgeDir = path.join(distDir, 'edge');
  try {
    fs.mkdirSync(edgeDir, { recursive: true });
    const probe = path.join(edgeDir, '.doctor-write-probe');
    fs.writeFileSync(probe, 'ok', 'utf8');
    fs.unlinkSync(probe);
    return pass(CHECK_DIST_WRITABLE, `dist/edge/ is writable (${edgeDir}).`);
  } catch (e: any) {
    return fail(
      CHECK_DIST_WRITABLE,
      `Cannot write to dist/edge/: ${e.message}. Check filesystem permissions — build will fail.`
    );
  }
}

function checkDependencies(cwd, spawnSyncImpl) {
  const spawnSync = spawnSyncImpl || require('child_process').spawnSync;
  // `npm ls --depth=0 --json` reports UNMET DEPENDENCY and invalid peer ranges
  // as top-level `problems[]` entries, so we don't have to re-scan node_modules.
  const res = spawnSync('npm', ['ls', '--depth=0', '--json'], {
    cwd,
    encoding: 'utf8',
  });
  // npm returns non-zero when problems exist, but still prints a valid JSON
  // tree on stdout. A truly catastrophic failure (npm missing) has empty stdout.
  if (!res || !res.stdout) {
    return warn(CHECK_DEPENDENCIES, 'Could not run `npm ls` (npm not on PATH?). Skipping dependency check.');
  }
  let parsed;
  try {
    parsed = JSON.parse(res.stdout);
  } catch (e: any) {
    return warn(CHECK_DEPENDENCIES, `Could not parse \`npm ls --json\` output: ${e.message}`);
  }
  const problems = Array.isArray(parsed.problems) ? parsed.problems : [];
  if (problems.length > 0) {
    return fail(
      CHECK_DEPENDENCIES,
      `npm reports dependency problems: ${problems.join('; ')}. Run \`npm install\` to resolve.`,
      { problems }
    );
  }
  return pass(CHECK_DEPENDENCIES, 'npm dependency tree is clean.');
}

function runDoctor(opts) {
  const cwd = (opts && opts.cwd) || process.cwd();
  const pkgRoot = (opts && opts.pkgRoot) || path.resolve(__dirname, '..');
  const envProvider = (opts && opts.envProvider) || ((name) => process.env[name]);
  const spawnSyncImpl = (opts && opts.spawnSync) || null;

  const pkgJsonPath = path.join(pkgRoot, 'package.json');
  let cdnSecurityVersion = 'unknown';
  try {
    cdnSecurityVersion = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8')).version;
  } catch (_) {
    /* best-effort only */
  }

  const checks = [];

  checks.push(checkNodeVersion(process.versions.node));

  const policyPath = resolvePolicyPath(cwd, opts && opts.policyPath);
  const policyExistsCheck = checkPolicyExists(policyPath);
  checks.push(policyExistsCheck);

  let parseResult: any = { ok: false, doc: null };
  let policyDoc = null;
  if (policyExistsCheck.status === 'pass') {
    parseResult = tryParsePolicy(policyPath);
    checks.push(checkPolicyParses(parseResult));
    if (parseResult.ok) policyDoc = parseResult.doc;
  } else {
    checks.push(skip(CHECK_POLICY_PARSES, 'Policy file missing; cannot parse.'));
  }

  checks.push(checkSchemaVersion(policyDoc));
  checks.push(checkEnvVars(policyDoc, envProvider));
  checks.push(checkDistWritable(cwd));
  checks.push(checkDependencies(cwd, spawnSyncImpl));

  const anyFail = checks.some((c) => c.status === 'fail');
  const exitCode = anyFail ? 1 : 0;

  const report = {
    generatedAt: new Date().toISOString(),
    cdnSecurityVersion,
    policyPath,
    exitCode,
    checks,
  };

  const reportPath = opts && opts.reportPath;
  if (reportPath) {
    const resolved = path.isAbsolute(reportPath) ? reportPath : path.join(cwd, reportPath);
    try {
      fs.writeFileSync(resolved, JSON.stringify(report, null, 2) + '\n', 'utf8');
    } catch (e: any) {
      // A report-write failure must not mask the actual doctor result, but we
      // surface it on stderr so CI can notice.
      console.error(`[doctor] failed to write report to ${resolved}: ${e.message}`);
    }
  }

  if (!opts || opts.log !== false) {
    for (const c of checks) {
      const marker = c.status === 'pass' ? 'OK   ' :
                     c.status === 'fail' ? 'FAIL ' :
                     c.status === 'warn' ? 'WARN ' : 'SKIP ';
      const stream = c.status === 'fail' ? console.error : console.log;
      stream(`[${marker}] ${c.name}: ${c.detail}`);
    }
    const summary = anyFail
      ? `[doctor] ${checks.filter((c) => c.status === 'fail').length} failing check(s). See above.`
      : `[doctor] all checks passed.`;
    (anyFail ? console.error : console.log)(summary);
  }

  return { exitCode, report };
}

module.exports = {
  runDoctor,
  collectReferencedEnvVars,
  resolvePolicyPath,
  checkNodeVersion,
  checkPolicyExists,
  checkPolicyParses,
  checkSchemaVersion,
  checkEnvVars,
  checkDistWritable,
  checkDependencies,
  tryParsePolicy,
  MIN_NODE_MAJOR,
  MIN_NODE_VERSION,
  SCHEMA_CURRENT_VERSION,
};
