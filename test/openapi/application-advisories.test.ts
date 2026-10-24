import { expect, test } from 'vitest';
import { AdvisoryCheckError, checkNextAdvisories } from '../../src/openapi/application-advisories';

function input(version = '14.2.24', deployment: 'self-hosted' | 'static-export' | 'unknown' = 'self-hosted') {
  const manifest = { name: 'app', version: '1.0.0', dependencies: { next: '*' }, scripts: { prepare: 'SECRET_DO_NOT_PRINT' } };
  const lock = { name: 'app', version: '1.0.0', lockfileVersion: 3, packages: {
    '': { name: 'app', version: '1.0.0', dependencies: { next: '*' } },
    'node_modules/next': { version, resolved: `https://registry.npmjs.org/next/-/next-${version}.tgz` },
  } };
  return { packageJson: JSON.stringify(manifest), packageLock: JSON.stringify(lock), deployment };
}

function advisory(ghsaId: string, range: string, cveId: string | null = null) {
  return { ghsa_id: ghsaId, cve_id: cveId, html_url: `https://github.com/advisories/${ghsaId}`,
    withdrawn_at: null, vulnerabilities: [{ package: { ecosystem: 'npm', name: 'next' },
      vulnerable_version_range: range }] };
}

function feed(data: unknown, headers: Record<string, string> = {}) {
  return async () => new Response(JSON.stringify(data), { status: 200, headers });
}

test('finds reviewed advisories for the locked Next version without claiming deployment protection', async () => {
  let requested = '';
  let settings: RequestInit | undefined;
  const result = await checkNextAdvisories(input(), async (url, init) => {
    requested = String(url); settings = init;
    return new Response(JSON.stringify([
      advisory('GHSA-f82v-jwr5-mffw', '>= 14.0.0, < 14.2.25', 'CVE-2025-29927'),
      advisory('GHSA-aaaa-bbbb-cccc', '>= 14.0.0, < 14.2.25', 'CVE-2026-12345'),
    ]), { status: 200 });
  });
  expect(requested).toBe('https://api.github.com/advisories?affects=next%4014.2.24&type=reviewed&per_page=100');
  expect(settings).toMatchObject({ redirect: 'error' });
  expect(settings?.signal).toBeInstanceOf(AbortSignal);
  expect(result).toMatchObject({ status: 'action-required', version: '14.2.24',
    source: 'github-reviewed-npm', findings: [
      { ghsaId: 'GHSA-aaaa-bbbb-cccc', status: 'unassessed' },
      { ghsaId: 'GHSA-f82v-jwr5-mffw', status: 'mitigation-candidate-available' },
    ] });
  expect(result.packageJsonDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
  expect(result.feedDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
  expect(JSON.stringify(result)).not.toContain('SECRET_DO_NOT_PRINT');
  expect(JSON.stringify(result)).not.toContain('protected');
});

test('reports a successful empty feed only after an exact supported version was checked', async () => {
  const result = await checkNextAdvisories(input('16.0.0'), feed([]));
  expect(result).toMatchObject({ status: 'no-reviewed-advisories', version: '16.0.0', findings: [] });
  expect(result.checkedAt).toMatch(/^\d{4}-\d\d-\d\dT/);
});

test('marks this middleware advisory inapplicable to static export, without generalizing to other advisories', async () => {
  const result = await checkNextAdvisories(input('14.2.24', 'static-export'), feed([
    advisory('GHSA-f82v-jwr5-mffw', '>= 14.0.0, < 14.2.25', 'CVE-2025-29927'),
    advisory('GHSA-aaaa-bbbb-cccc', '>= 14.0.0, < 14.2.25'),
  ]));
  expect(result.status).toBe('action-required');
  expect(result.findings).toEqual([
    expect.objectContaining({ ghsaId: 'GHSA-aaaa-bbbb-cccc', status: 'unassessed' }),
    expect.objectContaining({ ghsaId: 'GHSA-f82v-jwr5-mffw', status: 'not-applicable' }),
  ]);
});

test('does not call a static-export middleware advisory actionable', async () => {
  const result = await checkNextAdvisories(input('14.2.24', 'static-export'), feed([
    advisory('GHSA-f82v-jwr5-mffw', '>= 14.0.0, < 14.2.25', 'CVE-2025-29927'),
  ]));
  expect(result.status).toBe('not-applicable');
});

test('reports no direct production Next declaration without querying the advisory feed', async () => {
  const fixture = input();
  const manifest = JSON.parse(fixture.packageJson);
  const lock = JSON.parse(fixture.packageLock);
  delete manifest.dependencies.next;
  delete lock.packages[''].dependencies.next;
  let calls = 0;
  const report = await checkNextAdvisories({ ...fixture,
    packageJson: JSON.stringify(manifest), packageLock: JSON.stringify(lock),
  }, async () => { calls++; return new Response('[]'); });
  expect(report).toMatchObject({ status: 'not-declared', checkedAt: null, version: null, findings: [] });
  expect(calls).toBe(0);
});

test('does not query a feed when the installed version or deployment is unknown', async () => {
  let calls = 0;
  const fetcher = async () => { calls++; return new Response('[]'); };
  await expect(checkNextAdvisories(input('14.2.24', 'unknown'), fetcher)).rejects.toMatchObject({ code: 'APPLICATION_ANALYSIS_UNKNOWN' });
  const unsupported = input();
  const lock = JSON.parse(unsupported.packageLock); lock.lockfileVersion = 1;
  await expect(checkNextAdvisories({ ...unsupported, packageLock: JSON.stringify(lock) }, fetcher))
    .rejects.toMatchObject({ code: 'APPLICATION_ANALYSIS_UNKNOWN' });
  expect(calls).toBe(0);
});

test.each([
  [() => new Response('bad gateway', { status: 502 }), 'ADVISORY_FEED_UNAVAILABLE'],
  [() => new Response('{', { status: 200 }), 'ADVISORY_FEED_INVALID'],
  [() => new Response('[]', { status: 200, headers: { link: '<https://api.github.com/advisories?after=x>; rel="next"' } }), 'ADVISORY_FEED_INCOMPLETE'],
  [() => new Response('x'.repeat(4 * 1024 * 1024 + 1), { status: 200 }), 'ADVISORY_FEED_INVALID'],
])('does not turn unavailable, malformed, truncated or oversized feeds into a clean result', async (response, code) => {
  await expect(checkNextAdvisories(input('16.0.0'), async () => response())).rejects.toMatchObject({ code });
});

test('converts body stream failure into an unavailable feed error', async () => {
  const failing = new ReadableStream<Uint8Array>({ pull(controller) { controller.error(new Error('SECRET_DO_NOT_PRINT')); } });
  await expect(checkNextAdvisories(input('16.0.0'), async () => new Response(failing)))
    .rejects.toMatchObject({ code: 'ADVISORY_FEED_UNAVAILABLE' });
});

test('rejects a feed whose package or vulnerable range does not bind the locked version', async () => {
  const wrongPackage = advisory('GHSA-aaaa-bbbb-cccc', '>= 14.0.0, < 14.2.25');
  wrongPackage.vulnerabilities[0].package.name = 'other';
  for (const bad of [wrongPackage, advisory('GHSA-aaaa-bbbb-cccc', '>= 15.0.0'),
    advisory('GHSA-aaaa-bbbb-cccc', 'not-a-range')]) {
    await expect(checkNextAdvisories(input(), feed([bad]))).rejects.toBeInstanceOf(AdvisoryCheckError);
  }
});

test('rejects a catalog advisory with an unexpected CVE identity', async () => {
  await expect(checkNextAdvisories(input(), feed([
    advisory('GHSA-f82v-jwr5-mffw', '>= 14.0.0, < 14.2.25', 'CVE-2026-12345'),
  ]))).rejects.toMatchObject({ code: 'ADVISORY_FEED_INVALID' });
});
