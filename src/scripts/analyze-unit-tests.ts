import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { parseAnalyzeRecord, runAnalyze } from '../bin/analyze';

const cli = path.join(__dirname, '..', 'bin', 'cli.js');
const codes = ['JSON_SYNTAX', 'RECORD_TYPE', 'EVENT_MISSING', 'EVENT_VALUE', 'EVENT_UNKNOWN',
  'EVENT_ALIAS_CONFLICT', 'NESTED_MESSAGE', 'FIELD_VALUE', 'STATUS_VALUE'];
const hash = (file: string) => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const tests: Array<{ name: string; run: () => void | Promise<void> }> = [];
const test = (name: string, run: () => void | Promise<void>) => tests.push({ name, run });
type Counts = [number, number, number, number, number, number];
// These are CLI JSON results, intentionally independent of the implementation's internal types.
type Report = { summary: Record<string, any>; diagnostics: any; candidates: any[]; byBlockReason: any; byPolicyRoute: any };
const row = (value: unknown) => JSON.stringify(value);
const block = { event: 'block', uri: '/a' };
const monitor = { event: 'monitor', uri: '/a' };

function fixture(text: string, run: (input: string) => void): void {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'analyze-ac-'));
  const input = path.join(tmp, 'input.jsonl');
  try {
    fs.writeFileSync(input, text);
    const before = hash(input);
    try { run(input); } finally { assert.equal(hash(input), before, 'input hash changed'); }
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}
function cliRun(args: string[]) {
  const result = spawnSync(process.execPath, [cli, 'analyze', ...args], {
    encoding: 'utf8', timeout: 15000, maxBuffer: 8 * 1024 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  return result;
}
function check(name: string, lines: string[], expected: Counts, errors: string[] = [], verify?: (report: Report) => void, args: string[] = []) {
  test(name, () => fixture(lines.join('\n'), input => {
    const [total, parsed, invalid, analyzed, blocked, monitored] = expected;
    const status = total === 0 ? 'empty' : parsed === 0 ? 'invalid' : invalid > 0 ? 'partial' : 'complete';
    const expectedCounts = Object.fromEntries(codes.map(code => [`ANALYZE_${code}`, errors.filter(error => error === code).length]));
    const expectedStderr = status === 'complete' ? '' : `[${status === 'invalid' ? 'ERROR' : 'WARN'}] ANALYZE_INPUT_${status.toUpperCase()}\n`;
    let json: Report | undefined;
    for (const format of ['json', 'text']) {
      const r = cliRun(['--input', input, ...args, ...(format === 'json' ? ['--json'] : [])]);
      assert.equal(r.status, status === 'complete' ? 0 : 1);
      assert.equal(r.stderr, expectedStderr);
      assert.ok(r.stdout.endsWith('\n'));
      assert.ok(!r.stdout.includes(input));
      if (format === 'json') {
        json = JSON.parse(r.stdout) as Report;
        const s = json.summary;
        assert.deepEqual([s.totalLines, s.parsedLines, s.unparseableLines, s.analyzedEvents, s.blockEvents, s.monitorEvents], expected);
        assert.equal(s.totalLines, s.parsedLines + s.unparseableLines);
        assert.equal(s.analyzedEvents, s.parsedLines);
        assert.equal(s.inputStatus, status);
        assert.deepEqual(Object.keys(json.diagnostics.counts), codes.map(code => `ANALYZE_${code}`));
        assert.deepEqual(json.diagnostics.counts, expectedCounts);
        assert.equal(json.diagnostics.total, invalid);
        assert.equal(json.diagnostics.examples.length, Math.min(20, invalid));
        assert.equal(json.diagnostics.omitted, Math.max(0, invalid - 20));
        assert.deepEqual(json.diagnostics.examples.map((e: any) => e.code), errors.slice(0, 20).map(code => `ANALYZE_${code}`));
        verify?.(json);
      } else {
        assert.ok(r.stdout.includes(`input_status=${status}`));
        assert.ok(r.stdout.includes(`total_lines=${total} parsed_lines=${parsed} unparseable=${invalid}`));
        assert.ok(r.stdout.includes(`analyzed_events=${analyzed} block=${blocked} monitor=${monitored}`));
        assert.deepEqual(JSON.parse(r.stdout.match(/^\[analyze\] diagnostics=(.+)$/m)![1]), json!.diagnostics);
      }
    }
  }));
}
const valid = (name: string, value: unknown, blocked = 0, monitored = 0, verify?: (r: Report) => void) => check(name, [row(value)], [1, 1, 0, 1, blocked, monitored], [], verify);
const invalid = (name: string, value: unknown, code: string) => check(name, [row(value)], [1, 0, 1, 0, 0, 0], [code]);
function withField(record: Record<string, unknown>, alias: string, value: unknown): Record<string, unknown> {
  const [parent, child] = alias.split('.');
  return { ...record, [parent]: child ? { ...((record[parent] as object) ?? {}), [child]: value } : value };
}

check('A01 normal block + monitor', [row(block), row(monitor)], [2, 2, 0, 2, 1, 1], [], r => {
  assert.equal(r.byPolicyRoute['/a'].count, 2); assert.equal(r.candidates[0].count, 1);
});
check('A02 invalid records', ['{}', '[]', 'null'], [3, 0, 3, 0, 0, 0], ['EVENT_MISSING', 'RECORD_TYPE', 'RECORD_TYPE']);
check('A03 mixed records', [row(block), '{}', '{'], [3, 1, 2, 1, 1, 0], ['EVENT_MISSING', 'JSON_SYNTAX']);
invalid('A04 status without event', { status: 403 }, 'EVENT_MISSING');
check('A05 audit + error', [row({ event: 'audit', status: 403 }), row({ event: 'error', status: 503 })], [2, 2, 0, 2, 0, 0]);
check('A06 empty', [], [0, 0, 0, 0, 0, 0]);
check('A06 whitespace', ['', '  ', '\t', ''], [0, 0, 0, 0, 0, 0]);
valid('A07 synonymous event aliases', { ...block, event: ' BLOCK ', eventName: 'blocked', outcome: 'block' }, 1);
invalid('A08 conflicting event aliases', { event: 'allow', outcome: 'blocked' }, 'EVENT_ALIAS_CONFLICT');
for (const alias of ['event', 'eventName', 'outcome']) {
  for (const value of [null, '', ' ', 3, false, [], {}]) {
    invalid(`A09 ${alias}=${row(value)}`, { event: 'block', eventName: 'blocked', [alias]: value }, 'EVENT_VALUE');
  }
}
for (const value of ['surprise', '__proto__', 'constructor', 'toString']) invalid(`A10 unknown ${value}`, { event: value }, 'EVENT_UNKNOWN');
for (const alias of ['event', 'eventName', 'outcome']) {
  for (const value of ['allow', 'pass', 'passed', 'monitor', 'monitoring', 'logged', 'audit', 'error', 'block', 'blocked']) {
    valid(`A11 ${alias} ${value}`, { [alias]: ` ${value.toUpperCase()} ` }, Number(['block', 'blocked'].includes(value)), Number(['monitor', 'monitoring', 'logged'].includes(value)));
  }
}
check('A12 generated challenge events', [row({ event: 'challenge', status: 403, method: 'GET', uri: '/login', block_reason: 'js_challenge_required' }), row({ event: 'challenge_report', status: 200, method: 'GET', uri: '/login', block_reason: 'js_challenge_report' })], [2, 2, 0, 2, 0, 0], [], r => {
  assert.equal(r.candidates.length, 0); assert.equal(r.byPolicyRoute['/login'].count, 2);
});
valid('A13 missing route', { event: 'block' }, 1, 0, r => { assert.equal(r.byPolicyRoute.unknown.count, 1); assert.equal(r.candidates.length, 0); });
valid('A14 known policy route missing URI', { event: 'block', policy_route: '/known' }, 1, 0, r => {
  assert.deepEqual(r.candidates[0].events[0], { method: 'UNKNOWN', status: 0, uri: 'unknown', target: 'unknown' });
});
valid('A15 explicit unknown route', { event: 'block', uri: 'unknown' }, 1, 0, r => assert.equal(r.candidates[0].policyRoute, '/unknown'));
check('A15 missing and real unknown stay separate', [row({ event: 'block' }), row({ event: 'block', uri: '/unknown' })], [2, 2, 0, 2, 2, 0], [], r => {
  assert.equal(r.byPolicyRoute.unknown.count, 1); assert.equal(r.byPolicyRoute['/unknown'].count, 1); assert.equal(r.candidates.length, 1);
});
const fields = {
  method: ['method', 'httpRequest.method', 'request.method'],
  uri: ['uri', 'path', 'request.uri', 'request.path', 'httpRequest.uri', 'httpRequest.path'],
  policyRoute: ['policy_route', 'policyRoute', 'route', 'request.route'],
  target: ['target', 'platform', 'provider', 'runtime'],
  blockReason: ['block_reason', 'blockReason', 'reason'],
};
invalid('A16 invalid first alias is not rescued', { event: 'pass', method: null, request: { method: 'GET' } }, 'FIELD_VALUE');
for (const aliases of Object.values(fields)) {
  for (const alias of aliases) {
    for (const value of [null, '', ' ', 3, false, {}, []]) {
      invalid(`A16 ${alias}=${row(value)}`, withField({ event: 'pass' }, alias, value), 'FIELD_VALUE');
    }
  }
}
valid('A17 arbitrary method/provider', { event: 'pass', method: 'CUSTOM', request: { method: 'GET' }, provider: 'custom-edge' });
for (const [key, aliases] of Object.entries(fields)) {
  for (let start = 0; start < aliases.length; start++) {
    let record: Record<string, unknown> = { event: 'block', ...(key === 'uri' ? {} : { uri: '/a' }) };
    for (let index = start; index < aliases.length; index++) record = withField(record, aliases[index], `${key}-${index}`);
    valid(`A17 precedence ${key} starting ${aliases[start]}`, record, 1, 0, r => {
      const first = r.candidates[0], sample = first.events[0];
      const actual = key === 'policyRoute' ? first.policyRoute : key === 'blockReason' ? first.blockReason : sample[key];
      assert.equal(actual, `${key === 'uri' || key === 'policyRoute' ? '/' : ''}${key}-${start}`);
    });
  }
}
invalid('A18 lower priority field invalid', { event: 'pass', method: 'GET', request: { method: false } }, 'FIELD_VALUE');
for (const key of ['request', 'httpRequest']) for (const value of [null, [], false, 5, 'text']) invalid(`A19 ${key}=${row(value)}`, { event: 'pass', [key]: value }, 'FIELD_VALUE');
for (const key of ['status', 'statusCode']) {
  for (const value of [0, 100, 200, 599, '0', '100', '599', '0200', ' 200 ']) {
    valid(`A20 ${key}=${row(value)}`, { ...block, [key]: value }, 1, 0, r => assert.equal(r.candidates[0].events[0].status, Number(value)));
  }
  for (const value of [99, 600, -1, 200.5, true, null, '', ' ', '2e2', '0xc8', '200.0', '+200']) invalid(`A21 ${key}=${row(value)}`, { event: 'pass', [key]: value }, 'STATUS_VALUE');
}
check('A20 JSON number exponent', ['{"event":"pass","status":2e2}'], [1, 1, 0, 1, 0, 0]);
check('A21 non-finite JSON number', ['{"event":"pass","status":1e400}'], [1, 0, 1, 0, 0, 0], ['STATUS_VALUE']);
for (const literal of ['NaN', 'Infinity']) check(`A21 invalid JSON ${literal}`, [`{"event":"pass","status":${literal}}`], [1, 0, 1, 0, 0, 0], ['JSON_SYNTAX']);
valid('A22 explicit zero wins', { ...block, status: 0, statusCode: 403 }, 1, 0, r => assert.equal(r.candidates[0].events[0].status, 0));
invalid('A23 invalid lower status alias', { event: 'pass', status: 200, statusCode: false }, 'STATUS_VALUE');
valid('A24 one nested event', { message: row({ event: 'block', uri: '/inner' }) }, 1, 0, r => assert.equal(r.candidates[0].policyRoute, '/inner'));
valid('A25 direct free text', { event: 'pass', message: 'ordinary free text' });
valid('A26 outer event wins', { event: 'allow', message: row({ event: 'block', uri: '/inner' }) }, 0, 0, r => assert.equal(r.candidates.length, 0));
invalid('A27 invalid outer event is not rescued', { event: null, message: row(block) }, 'EVENT_VALUE');
for (const value of ['{', '[]', 'null', '3', '{}', {}, '', '"text"', true]) invalid(`A28 bad message ${row(value)}`, { uri: '/outer', message: value }, 'NESTED_MESSAGE');
invalid('A29 no recursive message', { message: row({ message: '{}' }) }, 'NESTED_MESSAGE');
valid('A30 no metadata composition', { uri: '/outer', message: row({ event: 'block' }) }, 1, 0, r => { assert.equal(r.candidates.length, 0); assert.equal(r.byPolicyRoute.unknown.count, 1); });
invalid('A31 nested unknown event', { message: row({ event: 'surprise' }) }, 'EVENT_UNKNOWN');
const special = ['__proto__', 'constructor', 'prototype', 'toString'];
check('A32 special keys', special.map(value => row({ ...block, block_reason: value, target: value })), [4, 4, 0, 4, 4, 0], [], r => {
  assert.equal(r.candidates.length, 4);
  for (const value of special) {
    assert.equal(Object.getOwnPropertyDescriptor(r.byBlockReason, value)?.value.count, 1);
    assert.equal(Object.getOwnPropertyDescriptor(r.byBlockReason[value].targets, value)?.value, 1);
    assert.equal(Object.getOwnPropertyDescriptor(r.byPolicyRoute['/a'].blockReasons, value)?.value, 1);
    assert.equal(Object.getOwnPropertyDescriptor(r.byPolicyRoute['/a'].targets, value)?.value, 1);
    assert.equal(r.byBlockReason[value].policyRoutes['/a'], 1);
    assert.deepEqual(r.candidates.find(c => c.blockReason === value).targets, [value]);
  }
});
check('A33 tuple identity', [row({ ...block, block_reason: 'a|/b', uri: '/c' }), row({ ...block, block_reason: 'a', uri: '/b|/c' })], [2, 2, 0, 2, 2, 0], [], r => {
  assert.deepEqual(r.candidates.map(c => [c.blockReason, c.policyRoute, c.count]), [['a', '/b|/c', 1], ['a|/b', '/c', 1]]);
});
for (let index = 0; index < 3; index++) {
  const lines = [row(block), row(monitor)]; lines.splice(index, 0, '{}');
  check(`A34 invalid line at ${index + 1}`, lines, [3, 2, 1, 2, 1, 1], ['EVENT_MISSING'], r => assert.equal(r.diagnostics.examples[0].line, index + 1));
}
check('A35 bounded diagnostics and physical line', ['', ...Array(25).fill('{}')], [25, 0, 25, 0, 0, 0], Array(25).fill('EVENT_MISSING'), r => assert.deepEqual(r.diagnostics.examples.map((e: any) => e.line), Array.from({ length: 20 }, (_, i) => i + 2)));
// A36 stays in programmatic-api-unit-tests.ts: the original #1020 privacy fixture.
test('A37 missing and unreadable input', () => fixture('', input => {
  for (const [file, code] of [[`${input}.missing`, 'INPUT_NOT_FOUND'], [path.dirname(input), 'INPUT_READ_FAILED']]) {
    for (const json of [false, true]) {
      const result = cliRun(['--input', file, ...(json ? ['--json'] : [])]);
      assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.equal(result.stderr, `[ERROR] ANALYZE_${code}\n`);
    }
  }
}));
test('A38 parser-level argument errors and help', () => fixture('', input => {
  for (const args of [[], ['--input'], ['--input', input, '--unknown-synthetic'], ['--input', input, '--min-count', '0'], ['--input', input, '--top', 'synthetic-not-a-number']]) {
    const result = cliRun(args); assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.equal(result.stderr, '[ERROR] ANALYZE_ARGUMENT_INVALID\n');
  }
  const help = cliRun(['--help']); assert.equal(help.status, 0); assert.equal(help.stderr, ''); assert.ok(help.stdout.includes('--input'));
}));
valid('A39 normalized-empty URI', { event: 'block', uri: '?q=synthetic' }, 1, 0, r => { assert.equal(r.candidates.length, 0); assert.equal(r.byPolicyRoute.unknown.count, 1); });
valid('A39 normalized-empty policy route does not fall back', { ...block, policy_route: '#synthetic' }, 1, 0, r => assert.equal(r.candidates.length, 0));

// A40 reads a genuinely backpressured pipe, not spawnSync's eagerly drained output.
test('A40 slow pipe output completes on exit 1', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'analyze-pipe-'));
  const input = path.join(tmp, 'input.jsonl');
  fs.writeFileSync(input, [...Array.from({ length: 1000 }, (_, i) => row({ event: 'block', uri: `/route-${i}` })), '{}'].join('\n'));
  const before = hash(input);
  try {
    const child = spawn(process.execPath, [cli, 'analyze', '--input', input, '--top', '1000', '--json'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let bytes = 0, stderr = '';
    const chunks: Buffer[] = [];
    const timeout = setTimeout(() => child.kill('SIGKILL'), 20000);
    let resume: ReturnType<typeof setTimeout> | undefined;
    try {
      child.stdout.pause();
      resume = setTimeout(() => child.stdout.resume(), 100);
      child.stdout.on('data', (chunk: Buffer) => {
        bytes += chunk.length; chunks.push(chunk); child.stdout.pause();
        if (bytes > 8 * 1024 * 1024) child.kill('SIGKILL');
        resume = setTimeout(() => child.stdout.resume(), 10);
      });
      child.stderr.on('data', chunk => { stderr += chunk.toString(); });
      const result = await new Promise<{ code: number | null; signal: string | null }>((resolve, reject) => {
        child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
      });
      assert.deepEqual(result, { code: 1, signal: null });
      const output = Buffer.concat(chunks).toString('utf8');
      assert.ok(bytes > 65536); assert.ok(output.endsWith('\n'));
      const report = JSON.parse(output);
      assert.deepEqual([report.summary.totalLines, report.summary.parsedLines, report.summary.unparseableLines, report.summary.analyzedEvents, report.summary.blockEvents, report.summary.monitorEvents], [1001, 1000, 1, 1000, 1000, 0]);
      assert.equal(report.summary.inputStatus, 'partial'); assert.equal(report.candidates.length, 1000);
      assert.equal(report.diagnostics.counts.ANALYZE_EVENT_MISSING, 1); assert.equal(report.diagnostics.total, 1);
      assert.deepEqual(report.diagnostics.examples, [{ line: 1001, code: 'ANALYZE_EVENT_MISSING' }]); assert.equal(report.diagnostics.omitted, 0);
      assert.equal(stderr, '[WARN] ANALYZE_INPUT_PARTIAL\n');
    } finally { clearTimeout(timeout); if (resume) clearTimeout(resume); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
  } finally { assert.equal(hash(input), before); fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('supplement parser own properties, non-finite status, and prototype invariance', () => {
  const before = Object.getOwnPropertyDescriptors(Object.prototype);
  assert.deepEqual(parseAnalyzeRecord(Object.create({ event: 'block' })), { ok: false, code: 'ANALYZE_EVENT_MISSING' });
  for (const status of [NaN, Infinity, -Infinity]) assert.deepEqual(parseAnalyzeRecord({ event: 'pass', status }), { ok: false, code: 'ANALYZE_STATUS_VALUE' });
  const request = Object.create({ method: 'INHERITED', uri: '/inherited' });
  const result = parseAnalyzeRecord({ event: 'block', request }); assert.ok(result.ok);
  assert.equal(result.event.method, 'UNKNOWN'); assert.equal(result.event.uri, null); assert.equal(result.event.policyRoute, null);
  for (const key of special) assert.ok(parseAnalyzeRecord({ event: 'block', block_reason: key, target: key }).ok);
  fixture(special.map(key => row({ ...block, block_reason: key, target: key })).join('\n'), input => {
    const report = runAnalyze({ input, minCount: 5, top: 20 });
    for (const key of special) {
      assert.equal(Object.getOwnPropertyDescriptor(report.byBlockReason, key)?.value.count, 1);
      assert.equal(Object.getOwnPropertyDescriptor(report.byPolicyRoute['/a'].blockReasons, key)?.value, 1);
      assert.equal(Object.getOwnPropertyDescriptor(report.byBlockReason[key].targets, key)?.value, 1);
    }
    assert.equal(JSON.parse(JSON.stringify(report)).candidates.length, 4);
  });
  assert.deepEqual(Object.getOwnPropertyDescriptors(Object.prototype), before);
});
check('supplement integer-like target order remains object-key order', ['10', '2', 'z', 'a'].map(target => row({ ...block, target })), [4, 4, 0, 4, 4, 0], [], r => {
  assert.deepEqual(r.candidates[0].targets, ['2', '10', 'z', 'a']);
  assert.deepEqual(r.candidates[0].events.map((e: any) => e.target), ['10', '2', 'z', 'a']);
});
check('supplement diagnostic validation precedence', [
  row({ event: 'surprise', eventName: null }), row({ event: 'surprise', eventName: 'block', outcome: 'pass' }),
  row({ event: 'block', outcome: 'pass', method: false }), row({ event: 'block', method: false, status: -1 }),
  row({ event: 'block', message: '{' }),
], [5, 1, 4, 1, 1, 0], ['EVENT_VALUE', 'EVENT_UNKNOWN', 'EVENT_ALIAS_CONFLICT', 'FIELD_VALUE']);
check('supplement stable candidate order, thresholds, target/sample order', [
  row({ ...block, block_reason: 'first', target: 'z' }), row({ ...block, block_reason: 'second', target: 'b' }),
  row({ ...block, block_reason: 'first', target: 'a' }), row({ ...block, block_reason: 'second', target: 'a' }),
], [4, 4, 0, 4, 4, 0], [], r => {
  assert.deepEqual(r.candidates.map(c => c.blockReason), ['first', 'second']);
  assert.deepEqual(r.candidates[0].targets, ['z', 'a']); assert.deepEqual(r.candidates[0].events.map((e: any) => e.target), ['z', 'a']);
}, ['--min-count', '2', '--top', '2']);
check('supplement min-count excludes high-frequency candidate', [row(block), row(block)], [2, 2, 0, 2, 2, 0], [], r => assert.equal(r.candidates.length, 0), ['--min-count', '1']);
check('supplement top limits samples and candidates', [row(block), row(block), row({ ...block, uri: '/b' }), row({ ...block, uri: '/b' })], [4, 4, 0, 4, 4, 0], [], r => { assert.equal(r.candidates.length, 1); assert.equal(r.candidates[0].events.length, 1); }, ['--top', '1']);

export async function runAnalyzeTests(): Promise<void> {
  let passed = 0;
  for (const { name, run } of tests) {
    try { await run(); passed++; console.log(`OK: analyze ${name}`); }
    catch (error) { console.error(`FAIL: analyze ${name}`, error); process.exitCode = 1; }
  }
  console.log(`analyze acceptance: ${passed}/${tests.length} cases passed (each report case checks JSON and text; A36 is in the parent suite)`);
}
