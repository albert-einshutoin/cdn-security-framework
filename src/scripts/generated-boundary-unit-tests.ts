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
  assert.equal(isGeneratedPackageArtifact('future.js'), true);
  assert.equal(isGeneratedPackageArtifact('future-module/index.d.ts'), true);
  assert.deepEqual(
    findGeneratedBoundaryViolations([
      'contract/index.js',
      'openapi/index.d.ts',
      'tests/golden/base/edge/viewer-request.js',
      'src/types/policy.d.ts',
    ]),
    ['contract/index.js', 'openapi/index.d.ts'],
  );
  assert.deepEqual(
    findGeneratedBoundaryViolations([
      'src/future-module/index.ts',
      'future-module/index.js',
      'future-module/index.d.ts',
    ]),
    ['future-module/index.d.ts', 'future-module/index.js'],
  );
  assert.deepEqual(
    findGeneratedBoundaryViolations(['future.js', 'future.d.ts']),
    ['future.d.ts', 'future.js'],
  );
});

test('golden, source, and documentation files are allowed', () => {
  assert.equal(isGeneratedPackageArtifact('tests/golden/base/edge/viewer-request.js'), false);
  assert.equal(isGeneratedPackageArtifact('src/types/policy.d.ts'), false);
  assert.equal(isGeneratedPackageArtifact('templates/aws/viewer-request.js'), false);
  assert.equal(isGeneratedPackageArtifact('runtimes/aws-cloudfront-functions/viewer-request.js'), false);
  assert.equal(isGeneratedPackageArtifact('examples/nestjs-contract/run-analysis.cjs'), false);
  assert.equal(isGeneratedPackageArtifact('examples/nestjs-contract/run-analysis.cjs.generated.js'), true);
  assert.equal(isGeneratedPackageArtifact('scripts/README.md'), false);
  assert.deepEqual(
    findGeneratedBoundaryViolations([
      'tests/golden/base/edge/viewer-request.js',
      'src/types/policy.d.ts',
      'scripts/README.md',
    ]),
    [],
  );
});

test('unknown generated-looking artifacts fail closed', () => {
  assert.deepEqual(
    findGeneratedBoundaryViolations([
      'docs/stale.js',
      '.github/generated.cjs',
      'ci/output.d.ts',
      'test/generated.js',
    ]),
    ['.github/generated.cjs', 'ci/output.d.ts', 'docs/stale.js', 'test/generated.js'],
  );
});
