#!/usr/bin/env node

const assert = require('assert');
const {
  errorMessage,
  isErrnoException,
  PolicyValidationError,
  isPolicyValidationError,
} = require('./lib/errors');

function test(name: string, fn: () => void) {
  try {
    fn();
    console.log('OK:', name);
  } catch (e: unknown) {
    console.error('FAIL:', name);
    console.error(e instanceof Error && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  }
}

test('errorMessage returns Error.message', () => {
  assert.strictEqual(errorMessage(new Error('boom')), 'boom');
});

test('errorMessage stringifies non-Error values', () => {
  assert.strictEqual(errorMessage('plain'), 'plain');
  assert.strictEqual(errorMessage(42), '42');
  assert.strictEqual(errorMessage(undefined), 'undefined');
});

test('isErrnoException detects code-bearing Error instances', () => {
  const err = Object.assign(new Error('missing'), { code: 'ENOENT' });
  assert.strictEqual(isErrnoException(err), true);
  if (isErrnoException(err)) {
    assert.strictEqual(err.code, 'ENOENT');
  }
  assert.strictEqual(isErrnoException(new Error('no code')), false);
  assert.strictEqual(isErrnoException('ENOENT'), false);
});

test('PolicyValidationError carries validationErrors and is detected by isPolicyValidationError', () => {
  const err = new PolicyValidationError('validation failed', ['field a', 'field b']);
  assert.strictEqual(err.message, 'validation failed');
  assert.strictEqual(err.name, 'PolicyValidationError');
  assert.deepStrictEqual(err.validationErrors, ['field a', 'field b']);
  assert.strictEqual(isPolicyValidationError(err), true);
  assert.strictEqual(isPolicyValidationError(new Error('other')), false);
});
