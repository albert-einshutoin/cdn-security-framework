import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { load } from 'js-yaml';
import { expect, test } from 'vitest';

const pin = 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333';
type Step = { uses?: unknown; with?: Record<string, unknown>; 'continue-on-error'?: unknown };

function requireVerifiedDownloads(steps: Step[]): void {
  const downloads = steps.filter(step => typeof step.uses === 'string' && /^actions\/download-artifact@/i.test(step.uses));
  assert(downloads.length > 0, 'artifact consumer workflows require downloads');
  for (const step of downloads) {
    assert.equal(step.uses, pin, 'download action must use the reviewed integrity-enforcing commit');
    // The next consumer step executes a downloaded harness, so a warning cannot establish trust.
    assert.equal(step.with?.['digest-mismatch'], 'error', 'artifact digest mismatch must stop before consumer execution');
    assert(step['continue-on-error'] === undefined || step['continue-on-error'] === false,
      'artifact verification failures cannot be continued');
  }
}

test('all artifact downloads stop on digest mismatch before consumer execution', () => {
  const steps: Step[] = [];
  for (const entry of fs.readdirSync('.github/workflows', { withFileTypes: true })) {
    if (!/\.ya?ml$/.test(entry.name)) continue;
    assert(entry.isFile(), 'workflow must be a regular file');
    const workflow = load(fs.readFileSync(path.join('.github/workflows', entry.name), 'utf8')) as {
      jobs: Record<string, { steps?: Step[] }>;
    };
    for (const job of Object.values(workflow.jobs)) steps.push(...(job.steps ?? []));
  }
  requireVerifiedDownloads(steps);
});

const unsafe: Array<[string, Partial<Step>]> = [
  ['mutable tag', { uses: 'actions/download-artifact@v8' }],
  ['warning-only action', { uses: 'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093' }],
  ['warn', { with: { 'digest-mismatch': 'warn' } }],
  ['ignore', { with: { 'digest-mismatch': 'ignore' } }],
  ['info', { with: { 'digest-mismatch': 'info' } }],
  ['missing explicit policy', { with: {} }],
  ['dynamic policy', { with: { 'digest-mismatch': '${{ inputs.policy }}' } }],
  ['continue on failure', { 'continue-on-error': true }],
  ['dynamic continuation', { 'continue-on-error': '${{ inputs.continue }}' }],
];
test.each(unsafe)('rejects %s at the artifact trust boundary', (_name, override) => {
  expect(() => requireVerifiedDownloads([{ uses: pin, with: { 'digest-mismatch': 'error' }, ...override }])).toThrow();
});

test('removing every download cannot vacuously pass the artifact gate', () => {
  expect(() => requireVerifiedDownloads([])).toThrow();
});
