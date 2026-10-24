import { createHash } from 'node:crypto';

const semver = require('semver') as {
  valid(version: string): string | null;
  validRange(range: string): string | null;
  satisfies(version: string, range: string): boolean;
};

export const MAX_APPLICATION_INPUT_BYTES = 8 * 1024 * 1024;
export type ApplicationDeployment = 'self-hosted' | 'static-export' | 'unknown';
export interface ApplicationDependencyInput {
  packageJson: string;
  packageLock: string;
  deployment: ApplicationDeployment;
}

export interface ApplicationDependencyAnalysis {
  catalog: 'nextjs-middleware-v1';
  coverage: 'CVE-2025-29927 only; other vulnerabilities and dependencies are unassessed';
  packageJsonDigest: string;
  packageLockDigest: string;
  deployment: ApplicationDeployment;
  findings: Array<{
    id: 'CVE-2025-29927';
    package: 'next';
    version: string | null;
    status: 'mitigation-generated' | 'not-affected-version' | 'not-applicable' | 'not-declared' | 'unknown';
    reason: string;
    source: string;
  }>;
}

export class ApplicationDependencyError extends Error {
  constructor(readonly code: 'APPLICATION_INPUT_INVALID' | 'APPLICATION_ANALYSIS_UNKNOWN', message: string) {
    super(message);
  }
}

function invalid(): never {
  throw new ApplicationDependencyError('APPLICATION_INPUT_INVALID', 'Expected bounded JSON objects for package.json and an npm package-lock.');
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

function parse(input: string): Record<string, unknown> {
  if (typeof input !== 'string' || Buffer.byteLength(input) > MAX_APPLICATION_INPUT_BYTES) invalid();
  try { return object(JSON.parse(input)) ?? invalid(); } catch { return invalid(); }
}

function declarations(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  const entries = object(value) ?? invalid();
  if (!Object.values(entries).every((entry) => typeof entry === 'string')) invalid();
  return entries as Record<string, string>;
}

function sameDeclarations(left: Record<string, string>, right: Record<string, string>): boolean {
  const keys = Object.keys(left);
  return keys.length === Object.keys(right).length
    && keys.every((key) => Object.hasOwn(right, key) && left[key] === right[key]);
}

// This catalog deliberately implements the vendor's header-presence workaround,
// not payload signatures. It covers framework routes absent from OpenAPI too.
export function analyzeApplicationDependencies(input: ApplicationDependencyInput): ApplicationDependencyAnalysis {
  if (!input || !['self-hosted', 'static-export', 'unknown'].includes(input.deployment)) invalid();
  const manifest = parse(input.packageJson);
  const lock = parse(input.packageLock);
  const result: ApplicationDependencyAnalysis = {
    catalog: 'nextjs-middleware-v1',
    coverage: 'CVE-2025-29927 only; other vulnerabilities and dependencies are unassessed',
    packageJsonDigest: `sha256:${createHash('sha256').update(input.packageJson).digest('hex')}`,
    packageLockDigest: `sha256:${createHash('sha256').update(input.packageLock).digest('hex')}`,
    deployment: input.deployment,
    findings: [{
      id: 'CVE-2025-29927', package: 'next', version: null, status: 'unknown',
      reason: 'unsupported-lockfile',
      source: 'https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw',
    }],
  };
  const finding = result.findings[0];
  if (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) return result;
  const packages = object(lock.packages);
  const root = object(packages?.['']);
  if (!root) { finding.reason = 'missing-lock-root'; return result; }
  for (const field of ['name', 'version'] as const) {
    if (manifest[field] !== root[field] || manifest[field] !== lock[field]) {
      throw new ApplicationDependencyError('APPLICATION_INPUT_INVALID', 'Package manifest and lock root identity differ.');
    }
  }
  for (const field of ['dependencies', 'optionalDependencies', 'devDependencies'] as const) {
    if (!sameDeclarations(declarations(manifest[field]), declarations(root[field]))) {
      throw new ApplicationDependencyError('APPLICATION_INPUT_INVALID', 'Package manifest and lock root dependency declarations differ.');
    }
  }
  const dependencies = declarations(manifest.dependencies);
  const optional = declarations(manifest.optionalDependencies);
  const spec = optional.next ?? dependencies.next;
  if (spec === undefined) {
    finding.status = Object.hasOwn(declarations(manifest.devDependencies), 'next') ? 'unknown' : 'not-declared';
    finding.reason = finding.status === 'unknown' ? 'next-is-development-only' : 'no-direct-production-next-declaration';
    return result;
  }
  if (optional.next && dependencies.next && optional.next !== dependencies.next) {
    finding.reason = 'conflicting-next-declarations'; return result;
  }
  const entry = object(packages?.['node_modules/next']);
  const version = entry?.version;
  if (!entry || entry.link || entry.dev || typeof version !== 'string'
    || !/^\d+\.\d+\.\d+$/.test(version) || !semver.valid(version)) {
    finding.reason = 'next-version-is-not-a-stable-registry-resolution'; return result;
  }
  // Local paths, aliases, tags and prereleases cannot establish the vendor's
  // released Next.js version. Never interpret their numeric substrings.
  if (!spec.trim() || !semver.validRange(spec) || !semver.satisfies(version, spec)
    || entry.resolved !== `https://registry.npmjs.org/next/-/next-${version}.tgz`) {
    finding.reason = 'next-specification-or-resolution-is-not-supported'; return result;
  }
  finding.version = version;
  const affected = semver.satisfies(version,
    '>=11.1.4 <12.3.5 || >=13.0.0 <13.5.9 || >=14.0.0 <14.2.25 || >=15.0.0 <15.2.3');
  if (!affected) {
    finding.status = 'not-affected-version'; finding.reason = 'outside-vendor-affected-version-ranges';
  } else if (input.deployment === 'static-export') {
    finding.status = 'not-applicable'; finding.reason = 'static-export-has-no-next-middleware-runtime';
  } else if (input.deployment === 'self-hosted') {
    finding.status = 'mitigation-generated'; finding.reason = 'block-external-middleware-subrequest-header-before-origin';
  } else {
    finding.reason = 'affected-next-deployment-is-unknown';
  }
  return result;
}
