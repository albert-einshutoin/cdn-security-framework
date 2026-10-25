import { createHash } from 'node:crypto';
import { analyzeApplicationDependencies, ApplicationDependencyError, type ApplicationDependencyInput } from './application-dependencies';

const semver = require('semver') as {
  validRange(range: string): string | null;
  satisfies(version: string, range: string): boolean;
};

const GITHUB_ADVISORIES = 'https://api.github.com/advisories';
const MAX_FEED_BYTES = 4 * 1024 * 1024;

export class AdvisoryCheckError extends Error {
  constructor(readonly code: 'ADVISORY_FEED_UNAVAILABLE' | 'ADVISORY_FEED_INVALID' | 'ADVISORY_FEED_INCOMPLETE') {
    super('GitHub reviewed advisory coverage could not be established.');
  }
}

export interface NextAdvisoryCheck {
  source: 'github-reviewed-npm';
  coverage: 'Direct production next dependency; curated vendor diagnostics and GitHub-reviewed public advisories only';
  catalog: 'nextjs-advisory-v2';
  checkedAt: string | null;
  feedDigest: string | null;
  packageJsonDigest: string;
  packageLockDigest: string;
  version: string | null;
  deployment: ApplicationDependencyInput['deployment'];
  status: 'not-declared' | 'no-reviewed-advisories' | 'not-applicable' | 'action-required';
  findings: Array<{
    ghsaId: string;
    cveId: string | null;
    url: string;
    status: 'mitigation-candidate-available' | 'not-applicable' | 'unassessed' | 'unknown' | 'upgrade-required';
  }>;
  catalogFindings: Array<{
    id: string;
    version: string | null;
    status: 'upgrade-required' | 'unknown' | 'not-affected-version' | 'not-applicable';
    reason: string;
    source: string;
  }>;
}

function invalid(): never {
  throw new AdvisoryCheckError('ADVISORY_FEED_INVALID');
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

async function readFeed(response: Response): Promise<{ value: unknown; digest: string }> {
  if (response.status !== 200) throw new AdvisoryCheckError('ADVISORY_FEED_UNAVAILABLE');
  if (/(?:^|[,;\s])rel\s*=\s*"?next"?(?:[,;\s]|$)/i.test(response.headers.get('link') ?? '')) {
    throw new AdvisoryCheckError('ADVISORY_FEED_INCOMPLETE');
  }
  const length = response.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_FEED_BYTES)) invalid();
  if (!response.body) invalid();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > MAX_FEED_BYTES) invalid();
      chunks.push(part.value);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  try {
    const body = Buffer.concat(chunks, bytes);
    return {
      value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)),
      digest: `sha256:${createHash('sha256').update(body).digest('hex')}`,
    };
  } catch { return invalid(); }
}

// GitHub uses commas between semver comparators in vulnerable_version_range.
function matchesNextVersion(value: unknown, version: string): boolean {
  const item = object(value) ?? invalid();
  const pkg = object(item.package) ?? invalid();
  if (pkg.ecosystem !== 'npm' || pkg.name !== 'next') return false;
  if (typeof item.vulnerable_version_range !== 'string') invalid();
  const range = item.vulnerable_version_range.replace(/,\s*/g, ' ');
  if (!semver.validRange(range)) invalid();
  return semver.satisfies(version, range);
}

export async function checkNextAdvisories(
  input: ApplicationDependencyInput,
  fetchAdvisories: typeof fetch = fetch,
): Promise<NextAdvisoryCheck> {
  const analysis = analyzeApplicationDependencies(input);
  const catalogFinding = analysis.findings[0];
  const report: NextAdvisoryCheck = {
    source: 'github-reviewed-npm',
    coverage: 'Direct production next dependency; curated vendor diagnostics and GitHub-reviewed public advisories only',
    catalog: analysis.catalog,
    checkedAt: null,
    feedDigest: null,
    packageJsonDigest: analysis.packageJsonDigest,
    packageLockDigest: analysis.packageLockDigest,
    version: catalogFinding.version,
    deployment: input.deployment,
    status: 'not-declared',
    findings: [],
    catalogFindings: analysis.findings.slice(1).map(({ id, version, status, reason, source }) => ({
      id, version, status: status as 'upgrade-required' | 'unknown' | 'not-affected-version' | 'not-applicable', reason, source,
    })),
  };
  if (catalogFinding.status === 'not-declared') return report;
  if (input.deployment === 'unknown' || catalogFinding.status === 'unknown' || !catalogFinding.version) {
    throw new ApplicationDependencyError('APPLICATION_ANALYSIS_UNKNOWN',
      'The installed Next.js version or deployment could not be established.');
  }

  const url = `${GITHUB_ADVISORIES}?affects=next%40${encodeURIComponent(catalogFinding.version)}&type=reviewed&per_page=100`;
  let response: Response;
  try {
    response = await fetchAdvisories(url, {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'cdn-security-framework' },
      redirect: 'error', signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new AdvisoryCheckError('ADVISORY_FEED_UNAVAILABLE');
  }
  let feed: { value: unknown; digest: string };
  try { feed = await readFeed(response); } catch (error) {
    if (error instanceof AdvisoryCheckError) throw error;
    throw new AdvisoryCheckError('ADVISORY_FEED_UNAVAILABLE');
  }
  if (!Array.isArray(feed.value) || feed.value.length > 100) invalid();
  const seen = new Set<string>();
  for (const raw of feed.value) {
    const item = object(raw) ?? invalid();
    const id = item.ghsa_id;
    if (typeof id !== 'string' || !/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(id)
      || seen.has(id) || item.html_url !== `https://github.com/advisories/${id}`
      || item.withdrawn_at !== null || !Array.isArray(item.vulnerabilities)) invalid();
    if (item.cve_id !== null && (typeof item.cve_id !== 'string' || !/^CVE-\d{4}-\d{4,}$/.test(item.cve_id))) invalid();
    seen.add(id);
    if (!item.vulnerabilities.some((value: unknown) => matchesNextVersion(value, catalogFinding.version as string))) invalid();
    if (id === 'GHSA-f82v-jwr5-mffw'
      && (item.cve_id !== 'CVE-2025-29927' || catalogFinding.status === 'not-affected-version')) invalid();
    const catalog = report.catalogFindings.find((finding) => finding.id === id);
    if (catalog?.status === 'not-affected-version') invalid();
    report.findings.push({
      ghsaId: id, cveId: item.cve_id as string | null, url: item.html_url as string,
      status: id === 'GHSA-f82v-jwr5-mffw'
        ? catalogFinding.status === 'not-applicable' ? 'not-applicable' : 'mitigation-candidate-available'
        : catalog?.status === 'unknown' || catalog?.status === 'upgrade-required' || catalog?.status === 'not-applicable'
          ? catalog.status : 'unassessed',
    });
  }
  if (catalogFinding.status === 'mitigation-generated'
    && !seen.has('GHSA-f82v-jwr5-mffw')) invalid();
  report.findings.sort((left, right) => left.ghsaId < right.ghsaId ? -1 : left.ghsaId > right.ghsaId ? 1 : 0);
  report.checkedAt = new Date().toISOString();
  report.feedDigest = feed.digest;
  const catalogActionable = report.catalogFindings.some(({ status }) => status === 'unknown' || status === 'upgrade-required');
  report.status = catalogActionable || report.findings.some(({ status }) => status !== 'not-applicable')
    ? 'action-required'
    : report.findings.length > 0 || report.catalogFindings.some(({ status }) => status === 'not-applicable')
      ? 'not-applicable' : 'no-reviewed-advisories';
  return report;
}
