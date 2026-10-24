import { createHash } from 'node:crypto';
import { expect, test } from 'vitest';
import { analyzeApplicationDependencies, ApplicationDependencyError, MAX_APPLICATION_INPUT_BYTES } from '../../src/openapi/application-dependencies';

function inputs(version = '14.2.24', spec = '*', deployment: 'self-hosted' | 'static-export' | 'unknown' = 'self-hosted') {
  const manifest = { name: 'app', version: '1.0.0', dependencies: { next: spec } };
  const lock = { name: 'app', version: '1.0.0', lockfileVersion: 3,
    packages: { '': structuredClone(manifest), 'node_modules/next': { version, resolved: `https://registry.npmjs.org/next/-/next-${version}.tgz` } } };
  return { manifest, lock, input: () => ({ packageJson: JSON.stringify(manifest), packageLock: JSON.stringify(lock), deployment }) };
}

test.each([
  ['11.1.3', false], ['11.1.4', true], ['12.3.4', true], ['12.3.5', false],
  ['13.0.0', true], ['13.5.8', true], ['13.5.9', false],
  ['14.0.0', true], ['14.2.24', true], ['14.2.25', false],
  ['15.0.0', true], ['15.2.2', true], ['15.2.3', false], ['16.0.0', false],
])('uses the vendor boundary for Next %s', (version, affected) => {
  expect(analyzeApplicationDependencies(inputs(version).input()).findings[0]).toMatchObject({
    version, status: affected ? 'mitigation-generated' : 'not-affected-version',
  });
});

test.each([2, 3])('accepts npm lockfile %i, binds exact source bytes, and stays deterministic', (lockfileVersion) => {
  const fixture = inputs(); fixture.lock.lockfileVersion = lockfileVersion;
  const input = fixture.input();
  const report = analyzeApplicationDependencies(input);
  expect(report).toEqual(analyzeApplicationDependencies(input));
  expect(report.packageJsonDigest).toBe(`sha256:${createHash('sha256').update(input.packageJson).digest('hex')}`);
  expect(report.packageLockDigest).toBe(`sha256:${createHash('sha256').update(input.packageLock).digest('hex')}`);
  expect(report.coverage).toContain('only');
  expect(JSON.stringify(report)).not.toContain('scripts');
});

test('distinguishes static export and unknown origin from a version match', () => {
  expect(analyzeApplicationDependencies(inputs('14.2.24', '*', 'static-export').input()).findings[0].status).toBe('not-applicable');
  expect(analyzeApplicationDependencies(inputs('14.2.24', '*', 'unknown').input()).findings[0]).toMatchObject({
    status: 'unknown', reason: 'affected-next-deployment-is-unknown',
  });
});

test.each(['^14.2.0', '~14.2.20', '>=14.0.0 <15.0.0', '14.2.24'])('checks stable locked versions against %s', (spec) => {
  expect(analyzeApplicationDependencies(inputs('14.2.24', spec).input()).findings[0].status).toBe('mitigation-generated');
});

test.each(['latest', 'npm:next@14.2.24', 'file:../next', 'workspace:*', '^15.0.0', ''])('does not guess versions from unsupported or mismatching %s', (spec) => {
  expect(analyzeApplicationDependencies(inputs('14.2.24', spec).input()).findings[0].status).toBe('unknown');
});

test.each(['14.2.24-canary.1', 'v14.2.24', '14.2', '014.2.24', '14.2.24+private'])('keeps nonstable or noncanonical lock version %s unknown', (version) => {
  expect(analyzeApplicationDependencies(inputs(version).input()).findings[0].status).toBe('unknown');
});

test('rejects mismatched manifests without disclosing contents', () => {
  const fixture = inputs(); fixture.manifest.dependencies.next = 'SECRET_DO_NOT_PRINT';
  expect(() => analyzeApplicationDependencies(fixture.input())).toThrow(ApplicationDependencyError);
  expect(() => analyzeApplicationDependencies(fixture.input())).not.toThrow(/SECRET_DO_NOT_PRINT/);
  fixture.manifest.dependencies.next = '*'; fixture.lock.name = 'other-app';
  expect(() => analyzeApplicationDependencies(fixture.input())).toThrow(/identity differ/);
});

test('does not interpret workspace links, missing entries, dev-only installs or arbitrary archives as vendor releases', () => {
  for (const entry of [undefined, { version: '14.2.24', link: true }, { version: '14.2.24', dev: true },
    { version: '14.2.24' }, { version: '14.2.24', resolved: 'file:next.tgz' },
    { version: '14.2.25', resolved: 'https://registry.npmjs.org/next/-/next-14.2.24.tgz' },
    { version: '14.2.24', resolved: 'https://evil.test/next-14.2.24.tgz' }]) {
    const fixture = inputs();
    (fixture.lock.packages as any)['node_modules/next'] = entry;
    expect(analyzeApplicationDependencies(fixture.input()).findings[0].status).toBe('unknown');
  }
});

test('reports no direct Next declaration without scanning nested modules, and does not mistake dev-only Next for production', () => {
  const fixture = inputs();
  delete (fixture.manifest.dependencies as any).next;
  delete (fixture.lock.packages[''].dependencies as any).next;
  expect(analyzeApplicationDependencies(fixture.input()).findings[0].status).toBe('not-declared');
  Object.assign(fixture.manifest, { devDependencies: { next: '*' } });
  Object.assign(fixture.lock.packages[''], { devDependencies: { next: '*' } });
  expect(analyzeApplicationDependencies(fixture.input()).findings[0].status).toBe('unknown');
});

test('limits unsupported analysis to unknown and rejects malformed or oversized input', () => {
  const fixture = inputs(); fixture.lock.lockfileVersion = 1;
  expect(analyzeApplicationDependencies(fixture.input()).findings[0].reason).toBe('unsupported-lockfile');
  for (const packageJson of ['[]', '{', 'null', 'x'.repeat(MAX_APPLICATION_INPUT_BYTES + 1)]) {
    expect(() => analyzeApplicationDependencies({ ...inputs().input(), packageJson })).toThrow(ApplicationDependencyError);
  }
});
