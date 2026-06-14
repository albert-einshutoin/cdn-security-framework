#!/usr/bin/env node

const assert = require('assert');
const {
  clampNumber,
  normalizeStringList,
  numberOr,
} = require('./lib/value-normalize');

function test(name: string, fn: () => void) {
  try {
    fn();
    console.log('OK:', name);
  } catch (e: any) {
    console.error('FAIL:', name);
    console.error(e && e.stack ? e.stack : e);
    process.exitCode = 1;
  }
}

test('clampNumber preserves legacy Number() coercion and fallback behavior', () => {
  assert.strictEqual(clampNumber(undefined, 1, 10, 5), 5);
  assert.strictEqual(clampNumber(null, 1, 10, 5), 1);
  assert.strictEqual(clampNumber('', 1, 10, 5), 1);
  assert.strictEqual(clampNumber('  ', 1, 10, 5), 1);
  assert.strictEqual(clampNumber('5', 1, 10, 3), 5);
  assert.strictEqual(clampNumber(Number.NaN, 1, 10, 5), 5);
  assert.strictEqual(clampNumber(Infinity, 1, 10, 5), 5);
  assert.strictEqual(clampNumber(true, 1, 10, 5), 1);
  assert.strictEqual(clampNumber(-10, 1, 10, 5), 1);
  assert.strictEqual(clampNumber(99, 1, 10, 5), 10);
});

test('numberOr preserves legacy Number(x) || fallback behavior', () => {
  assert.strictEqual(numberOr(0, 10), 10);
  assert.strictEqual(numberOr('0', 10), 10);
  assert.strictEqual(numberOr('', 10), 10);
  assert.strictEqual(numberOr(Number.NaN, 10), 10);
  assert.strictEqual(numberOr(7, 10), 7);
  assert.strictEqual(numberOr('7', 10), 7);
});

test('normalizeStringList trims strings, drops non-strings and empties, and applies casing', () => {
  assert.deepStrictEqual(normalizeStringList('GET'), []);
  assert.deepStrictEqual(normalizeStringList([' GET ', 7, '', 'Post'], 'lower'), ['get', 'post']);
  assert.deepStrictEqual(normalizeStringList([' us ', 'Jp', false], 'upper'), ['US', 'JP']);
  assert.deepStrictEqual(normalizeStringList([' /Admin ', 'Docs ']), ['/Admin', 'Docs']);
});
