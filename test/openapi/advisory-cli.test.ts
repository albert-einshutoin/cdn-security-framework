import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Command } from 'commander';
import { afterEach, expect, test, vi } from 'vitest';
import { registerOpenApiInspectCommand } from '../../src/bin/commands/openapi-inspect';

const workspaces: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  process.exitCode = 0;
  for (const directory of workspaces.splice(0)) fs.rmSync(directory, { recursive: true, force: true });
});

function workspace() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-advisory-cli-'));
  workspaces.push(directory);
  const manifest = { name: 'app', version: '1.0.0', dependencies: { next: '*' } };
  const lock = { name: 'app', version: '1.0.0', lockfileVersion: 3, packages: {
    '': manifest, 'node_modules/next': { version: '14.2.24',
      resolved: 'https://registry.npmjs.org/next/-/next-14.2.24.tgz' },
  } };
  fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify(manifest));
  fs.writeFileSync(path.join(directory, 'package-lock.json'), JSON.stringify(lock));
  return directory;
}

async function run(directory: string) {
  const program = new Command();
  registerOpenApiInspectCommand(program, {
    pkgRoot: process.cwd(),
    evaluatePolicyCapabilities: () => ({ findings: [] }),
    validatePolicy: () => ({ ok: true, errors: [] }),
  });
  await program.parseAsync(['advisory', 'check', '--workspace-root', directory,
    '--package-json', 'package.json', '--package-lock', 'package-lock.json',
    '--deployment', 'self-hosted'], { from: 'user' });
}

test('CLI emits a bounded JSON report and exits 2 when a reviewed advisory needs action', async () => {
  const directory = workspace();
  vi.stubGlobal('fetch', async () => new Response(JSON.stringify([{
    ghsa_id: 'GHSA-f82v-jwr5-mffw', cve_id: 'CVE-2025-29927',
    html_url: 'https://github.com/advisories/GHSA-f82v-jwr5-mffw', withdrawn_at: null,
    vulnerabilities: [{ package: { ecosystem: 'npm', name: 'next' }, vulnerable_version_range: '>= 14.0.0, < 14.2.25' }],
  }])));
  const output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  await run(directory);
  expect(process.exitCode).toBe(2);
  expect(error).not.toHaveBeenCalled();
  const report = JSON.parse(String(output.mock.calls[0][0]));
  expect(report).toMatchObject({ status: 'action-required', version: '14.2.24', findings: [
    { status: 'mitigation-candidate-available' },
  ] });
  expect(JSON.stringify(report)).not.toContain(directory);
});

test('CLI refuses escaped inputs before any network request or report', async () => {
  const directory = workspace();
  fs.unlinkSync(path.join(directory, 'package.json'));
  fs.symlinkSync(path.join(os.tmpdir(), 'outside-package.json'), path.join(directory, 'package.json'));
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  const output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  await run(directory);
  expect(process.exitCode).toBe(1);
  expect(fetcher).not.toHaveBeenCalled();
  expect(output).not.toHaveBeenCalled();
  expect(error.mock.calls[0][0]).toContain('APPLICATION_INPUT_INVALID');
});

test('CLI reports absent direct Next as unverified with exit 1', async () => {
  const directory = workspace();
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
  const lock = JSON.parse(fs.readFileSync(path.join(directory, 'package-lock.json'), 'utf8'));
  delete manifest.dependencies.next;
  delete lock.packages[''].dependencies.next;
  fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify(manifest));
  fs.writeFileSync(path.join(directory, 'package-lock.json'), JSON.stringify(lock));
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  const output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  await run(directory);
  expect(process.exitCode).toBe(1);
  expect(JSON.parse(String(output.mock.calls[0][0])).status).toBe('not-declared');
  expect(fetcher).not.toHaveBeenCalled();
});
