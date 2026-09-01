#!/usr/bin/env node

import assert = require('node:assert/strict');
import { findGeneratedBoundaryViolations, isGeneratedPackageArtifact } from './check-generated-boundary';

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log('OK:', name);
  } catch (error: unknown) {
    console.error('FAIL:', name);
    console.error(error instanceof Error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  }
}

test('generated package outputs are detected', () => {
  assert.equal(isGeneratedPackageArtifact('contract/index.js'), true);
  assert.equal(isGeneratedPackageArtifact('source/nestjs/index.d.ts'), true);
  assert.deepEqual(
    findGeneratedBoundaryViolations([
      'contract/index.js',
      'openapi/index.d.ts',
      'tests/golden/base/edge/viewer-request.js',
      'src/types/policy.d.ts',
    ]),
    ['contract/index.js', 'openapi/index.d.ts'],
  );
});

test('golden, source, and documentation files are allowed', () => {
  assert.equal(isGeneratedPackageArtifact('tests/golden/base/edge/viewer-request.js'), false);
  assert.equal(isGeneratedPackageArtifact('src/types/policy.d.ts'), false);
  assert.equal(isGeneratedPackageArtifact('scripts/README.md'), false);
  assert.deepEqual(findGeneratedBoundaryViolations(['tests/golden/base/edge/viewer-request.js', 'src/types/policy.d.ts', 'scripts/README.md']), []);
});
