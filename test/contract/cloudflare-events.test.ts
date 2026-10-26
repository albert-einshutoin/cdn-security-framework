import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { reviewCloudflareEvents, type CloudflareEventFixtureHeader, type CloudflareEventFixtureRecord } from '../../src/bin/cloudflare-events';

const header: CloudflareEventFixtureHeader = {
  version: 1, scope: 'synthetic-cloudflare-events', sourceSha256: 'a'.repeat(64),
  capturedAtMs: 3000, period: { fromMs: 1000, toMs: 2000 }, sampling: { kind: 'none', rate: 1 }, missing: [],
};
const event = (extra: Partial<CloudflareEventFixtureRecord> = {}): CloudflareEventFixtureRecord => ({
  observedAtMs: 1500, source: 'http', action: 'allow', status: 200, path: '/index.html',
  ruleSource: 'http', ruleIdSha256: null, policyRouteSha256: null, attribution: 'unmatched', ...extra,
});
const fixture = (records: unknown[], metadata: unknown = header) => Buffer.from([metadata, ...records].map(x => JSON.stringify(x)).join('\n') + '\n');

describe('bounded synthetic Cloudflare Events review', () => {
  it('distinguishes reported WAF block, 404, ordinary200, sensitive200 and unknown without asserting security', () => {
    const r = reviewCloudflareEvents(fixture([
      event({ source: 'waf', action: 'block', status: 403, path: '/private', ruleSource: 'custom-waf', ruleIdSha256: 'b'.repeat(64) }),
      event({ status: 404, path: '/missing.php' }), event(),
      event({ path: '/.env' }), event({ action: 'challenge', source: 'waf', status: 403 }),
    ]));
    expect(r.observations.map(x => x.inference.classification)).toEqual(['WAF_BLOCK_REPORTED', 'HTTP_404_NOT_SERVED', 'HTTP_200_REPORTED', 'REVIEW_SENSITIVE_PATH_200', 'UNKNOWN']);
    expect(r.summary.eventCount).toBe(5); expect(r.summary.requests).toBe('UNKNOWN');
    expect(r.candidates).toHaveLength(1); expect(r.candidates[0]).toMatchObject({ line: 5, content: 'UNKNOWN' });
    expect(r).toMatchObject({ mode: 'review-only', automaticApply: false, securityVerdict: 'UNKNOWN' });
  });
  it('preserves the observed status separately from the review inference', () => {
    const r = reviewCloudflareEvents(fixture([event({ status: 200, path: '/wp-config.php' })]));
    expect(r.observations[0].observed.status).toBe(200);
    expect(r.observations[0].inference).toMatchObject({ classification: 'REVIEW_SENSITIVE_PATH_200', content: 'UNKNOWN', wafEffectiveness: 'UNKNOWN' });
    expect(r.observations[0].inference.reasonCodes).toContain('CONTENT_NOT_OBSERVED');
  });
  it('retains sampling and missing information without estimating requests or effectiveness', () => {
    const r = reviewCloudflareEvents(fixture([event()], { ...header, sampling: { kind: 'sampled', rate: 0.1 }, missing: ['events', 'attribution'] }));
    expect(r.provenance?.sampling).toEqual({ kind: 'sampled', rate: 0.1 });
    expect(r.provenance?.missing).toEqual(['events', 'attribution']);
    expect(r.summary).toMatchObject({ inputStatus: 'partial', eventCount: 1, requests: 'UNKNOWN' });
    expect(JSON.stringify(r)).not.toMatch(/defenseRate|effectivenessPercent|requestCount/);
  });
  it('never copies a path/query/credential into output and does not modify bytes', () => {
    const input = fixture([event({ path: '/.env?token=synthetic_secret_only#cookie=synthetic_cookie' })]);
    const before = Buffer.from(input); const r = reviewCloudflareEvents(input); const text = JSON.stringify(r);
    for (const raw of ['/.env', 'synthetic_secret_only', 'synthetic_cookie', 'token=', 'cookie=']) expect(text).not.toContain(raw);
    expect(r.candidates[0].pathSha256).toMatch(/^[a-f0-9]{64}$/); expect(input).toEqual(before);
  });
  it('reports unsupported versions as UNKNOWN without interpreting v1 event bodies', () => {
    const r = reviewCloudflareEvents(Buffer.from(JSON.stringify({ version: 2, scope: 'synthetic-cloudflare-events' }) + '\nnot v1 JSON\n'));
    expect(r.summary).toMatchObject({ inputStatus: 'unknown', eventCount: 1, unknownEvents: 1 });
    expect(r.reasonCodes).toContain('VERSION_UNSUPPORTED'); expect(r.observations).toEqual([]); expect(r.candidates).toEqual([]);
  });
  it('rejects malformed input with a fixed code and no raw text', () => {
    expect(() => reviewCloudflareEvents(Buffer.from('synthetic_bad_secret{'))).toThrow('ANALYZE_CLOUDFLARE_JSON_INVALID');
  });
  it('applies the line budget to whitespace-only lines before ignoring blanks', () => {
    expect(() => reviewCloudflareEvents(Buffer.concat([fixture([event()]), Buffer.from(' '.repeat(8193))]))).toThrow('ANALYZE_CLOUDFLARE_SIZE_LIMIT');
  });
  it('budgets raw physical line bytes including a leading UTF8 BOM', () => {
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    const boundary = Buffer.concat([bom, Buffer.from(JSON.stringify(header).padEnd(8189))]);
    expect(boundary.length).toBe(8192); expect(reviewCloudflareEvents(boundary).summary.inputStatus).toBe('empty');
    const oversized = Buffer.concat([bom, Buffer.from(JSON.stringify(header).padEnd(8192))]);
    expect(oversized.length).toBe(8195); expect(() => reviewCloudflareEvents(oversized)).toThrow('ANALYZE_CLOUDFLARE_SIZE_LIMIT');
  });
  it('counts only events and bounds candidates without extrapolating repeated records into requests', () => {
    const r = reviewCloudflareEvents(fixture(Array.from({ length: 30 }, () => event({ path: '/.env' }))), 2);
    expect(r.summary).toMatchObject({ eventCount: 30, requests: 'UNKNOWN', reviewCandidates: 30, omittedCandidates: 28 });
    expect(r.candidates.map(c => c.line)).toEqual([2, 3]);
  });
  it('counts exactly1000 events and rejects1001 before interpreting the format', () => {
    expect(reviewCloudflareEvents(fixture(Array(1000).fill(event()))).summary.eventCount).toBe(1000);
    expect(() => reviewCloudflareEvents(fixture(Array(1001).fill({}), { version: 2, scope: header.scope }))).toThrow('ANALYZE_CLOUDFLARE_SIZE_LIMIT');
  });
  it('accepts an8192byte line and rejects8193bytes including before an unsupported version', () => {
    const line = JSON.stringify(event()).padEnd(8192);
    expect(reviewCloudflareEvents(Buffer.from(JSON.stringify(header) + '\n' + line)).summary.eventCount).toBe(1);
    expect(() => reviewCloudflareEvents(Buffer.from(JSON.stringify({ version: 2, scope: header.scope }) + '\n' + line + ' '))).toThrow('ANALYZE_CLOUDFLARE_SIZE_LIMIT');
  });
  it('rejects oversized bytes and invalidUTF8 without echoing input', () => {
    expect(() => reviewCloudflareEvents(Buffer.alloc(1048577))).toThrow('ANALYZE_CLOUDFLARE_SIZE_LIMIT');
    expect(() => reviewCloudflareEvents(new Uint8Array([0xc0, 0xaf]))).toThrow('ANALYZE_CLOUDFLARE_UTF8_INVALID');
  });
  it.each([0, -1, 1.5, 101, NaN, Infinity])('rejects invalid candidate top %s', top => {
    expect(() => reviewCloudflareEvents(fixture([event()]), top)).toThrow('ANALYZE_CLOUDFLARE_ARGUMENT_INVALID');
  });
  it.each([
    ['status', 99, 'STATUS_INVALID'], ['status', 600, 'STATUS_INVALID'], ['status', '200', 'STATUS_INVALID'],
    ['observedAtMs', -1, 'TIME_INVALID'], ['ruleIdSha256', 'synthetic_bad_identity', 'IDENTITY_INVALID'],
    ['path', 'https://synthetic.invalid/.env', 'PATH_INVALID'], ['path', '/foo\nbar', 'PATH_INVALID'],
    ['path', '/foo\\bar', 'PATH_INVALID'], ['path', '//' + 'example', 'PATH_INVALID'], ['path', '/' + 'x'.repeat(2048), 'PATH_INVALID'],
    ['source', null, 'SHAPE_INVALID'],
  ])('rejects malformed known field %s=%s', (key, value, suffix) => {
    expect(() => reviewCloudflareEvents(fixture([{ ...event(), [key]: value }]))).toThrow('ANALYZE_CLOUDFLARE_' + suffix);
  });
  it.each(['cookie', 'body', 'clientIP', 'token', 'unexpected'])('rejects extra %s fields without a broad input fallback', key => {
    expect(() => reviewCloudflareEvents(fixture([{ ...event(), [key]: 'synthetic_only' }]))).toThrow('ANALYZE_CLOUDFLARE_SHAPE_INVALID');
  });
  it('rejects malformed metadata, duplicate missing entries and reversed times', () => {
    for (const h of [
      { ...header, missing: ['events', 'events'] }, { ...header, period: { fromMs: 2000, toMs: 1000 } },
      { ...header, capturedAtMs: 1000 }, { ...header, sampling: { kind: 'none', rate: 0.5 } },
    ]) expect(() => reviewCloudflareEvents(fixture([event()], h))).toThrow(/^ANALYZE_CLOUDFLARE_/);
  });
  it('keeps unknown period/sampling/source metadata explicit', () => {
    const r = reviewCloudflareEvents(fixture([event()], { ...header, sourceSha256: null, capturedAtMs: null, period: { fromMs: null, toMs: null }, sampling: { kind: 'unknown', rate: null } }));
    expect(r.reasonCodes).toEqual(expect.arrayContaining(['SOURCE_MISSING', 'CAPTURE_TIME_MISSING', 'PERIOD_MISSING', 'SAMPLING_UNKNOWN']));
    expect(r.summary).toMatchObject({ inputStatus: 'unknown', unknownEvents: 1, requests: 'UNKNOWN' });
  });
  it.each([
    { observedAtMs: 999 }, { observedAtMs: 2001 }, { path: '/%2eenv' }, { path: '/a/../.env' }, { path: '/ユニコード' },
    { source: 'future-source' }, { action: 'future-action' }, { ruleSource: 'future-rule-source' },
    { source: 'http', action: 'block', status: 403 }, { source: 'waf', action: 'block', status: 200, ruleSource: 'custom-waf' },
  ])('retains unsupported/conflicting/out-of-period observations as UNKNOWN %#', extra => {
    const r = reviewCloudflareEvents(fixture([{ ...event(), ...extra }]));
    expect(r.observations[0].inference.classification).toBe('UNKNOWN'); expect(r.candidates).toEqual([]);
    expect(r.summary.inputStatus).toBe('unknown'); expect(JSON.stringify(r)).not.toContain('future-');
  });
  it('keeps declared and ambiguous attribution separate from HTTP status without trusting it', () => {
    const r = reviewCloudflareEvents(fixture([event({ attribution: 'declared', ruleIdSha256: 'b'.repeat(64), policyRouteSha256: 'c'.repeat(64) }), event({ attribution: 'ambiguous' })]));
    expect(r.observations[0].inference.reasonCodes).toContain('ATTRIBUTION_NOT_ATTESTED');
    expect(r.observations[1].inference.reasonCodes).toContain('ATTRIBUTION_AMBIGUOUS'); expect(r.securityVerdict).toBe('UNKNOWN');
  });
  it.each([
    ['attribution', 200, '/index.html', 'HTTP_200_REPORTED', 'ATTRIBUTION_UNKNOWN'],
    ['attribution', 404, '/absent', 'HTTP_404_NOT_SERVED', 'ATTRIBUTION_UNKNOWN'],
    ['attribution', 200, '/.env', 'REVIEW_SENSITIVE_PATH_200', 'ATTRIBUTION_UNKNOWN'],
    ['ruleSource', 200, '/index.html', 'HTTP_200_REPORTED', 'RULE_SOURCE_UNKNOWN'],
    ['ruleSource', 404, '/absent', 'HTTP_404_NOT_SERVED', 'RULE_SOURCE_UNKNOWN'],
    ['ruleSource', 200, '/.env', 'REVIEW_SENSITIVE_PATH_200', 'RULE_SOURCE_UNKNOWN'],
  ])('keeps supported HTTP observations but makes missing %s metadata partial (%s %s)', (key, status, pathname, classification, reason) => {
    const r = reviewCloudflareEvents(fixture([{ ...event({ status: status as number, path: pathname as string }), [key]: 'unknown' }]));
    expect(r.summary.inputStatus).toBe('partial');
    expect(r.observations[0].inference.classification).toBe(classification); expect(r.observations[0].inference.reasonCodes).toContain(reason);
    expect(r.observations[0].observed).toMatchObject({ [key]: 'unknown', status });
    expect(r.candidates).toHaveLength(pathname === '/.env' ? 1 : 0); expect(r.securityVerdict).toBe('UNKNOWN');
  });
  it.each(['ambiguous', 'declared'] as const)('does not call unresolved %s attribution complete', attribution => {
    const r = reviewCloudflareEvents(fixture([event({ attribution })]));
    expect(r.summary.inputStatus).toBe('partial'); expect(r.observations[0].observed.attribution).toBe(attribution);
  });
  it('keeps404 out of sensitive200 candidates and reported WAF block separate from HTTP status', () => {
    const r = reviewCloudflareEvents(fixture([event({ path: '/.env', status: 404 }), event({ path: null, source: 'waf', ruleSource: 'managed-waf', action: 'block', status: null })]));
    expect(r.observations.map(o => o.inference.classification)).toEqual(['HTTP_404_NOT_SERVED', 'WAF_BLOCK_REPORTED']); expect(r.candidates).toEqual([]);
  });
  it.each(['/.env.production.local', '/backup/credentials.json.bak', '/keys/id_rsa.bak'])('keeps common secret-file suffix variants review-only: %s', pathname => {
    const r = reviewCloudflareEvents(fixture([event({ path: pathname })]));
    expect(r.observations[0].inference.classification).toBe('REVIEW_SENSITIVE_PATH_200');
    expect(r.candidates[0].content).toBe('UNKNOWN');
  });
  it('handles CRLF/blank lines with physical line numbers and is deterministic', () => {
    const input = Buffer.from('\r\n' + JSON.stringify(header) + '\r\n\r\n' + JSON.stringify(event({ path: '/.env' })) + '\r\n');
    const r = reviewCloudflareEvents(input); expect(r.candidates[0].line).toBe(4); expect(reviewCloudflareEvents(input)).toEqual(r);
  });
  it('hashes the literal path independently of query/hash and records actual input byte identity', () => {
    const a = reviewCloudflareEvents(fixture([event({ path: '/.env?a=synthetic1#x' })]));
    const b = reviewCloudflareEvents(fixture([event({ path: '/.env?b=synthetic2#y' })]));
    expect(a.observations).toEqual(b.observations); expect(a.input.sha256).not.toBe(b.input.sha256);
  });
  it('keeps empty input and empty event inventory explicit', () => {
    expect(reviewCloudflareEvents(Buffer.from('  \n')).summary.inputStatus).toBe('empty');
    expect(reviewCloudflareEvents(fixture([])).summary).toMatchObject({ eventCount: 0, inputStatus: 'empty' });
  });
  it('does not accept monitor logs or mixed v1 headers as Cloudflare events', () => {
    expect(() => reviewCloudflareEvents(Buffer.from('{"event":"block"}'))).toThrow('ANALYZE_CLOUDFLARE_SCOPE_INVALID');
    expect(() => reviewCloudflareEvents(fixture([header]))).toThrow('ANALYZE_CLOUDFLARE_SHAPE_INVALID');
  });
  it('classifies the shipped28-event synthetic example with an independent expected inventory', () => {
    const r = reviewCloudflareEvents(fs.readFileSync('examples/sample-cloudflare-events.jsonl'));
    expect(r.summary).toMatchObject({ eventCount: 28, inputStatus: 'partial', reviewCandidates: 5, requests: 'UNKNOWN' });
    expect(r.summary.counts).toEqual({ WAF_BLOCK_REPORTED: 4, HTTP_404_NOT_SERVED: 6, HTTP_200_REPORTED: 8, REVIEW_SENSITIVE_PATH_200: 5, UNKNOWN: 5 });
    const text = JSON.stringify(r); for (const raw of ['/.env', '/wp-config.php', '/.git/config', '/backup/credentials', '/id_rsa']) expect(text).not.toContain(raw);
  });
});

describe('actual Cloudflare Events CLI', () => {
  function cli(records: unknown[], args: string[], metadata: unknown = header) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-cf-events-'));
    try {
      const input = path.join(directory, 'fixture.jsonl'), bytes = fixture(records, metadata); fs.writeFileSync(input, bytes);
      const result = spawnSync(process.execPath, ['bin/cli.js', 'analyze', '--input', input, ...args], { cwd: process.cwd(), encoding: 'utf8', timeout: 15000 });
      expect(result.error).toBeUndefined(); expect(result.signal).toBeNull(); expect(fs.readFileSync(input)).toEqual(bytes);
      expect(result.stdout).not.toContain(directory); expect(result.stderr).not.toContain(directory); return result;
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  }
  it('emits JSON and text for the explicit format with supported observations', () => {
    const json = cli([event({ path: '/.env?token=synthetic_secret' })], ['--format', 'cloudflare-events', '--json']);
    expect(json.status).toBe(0); expect(json.stderr).toBe(''); expect(JSON.parse(json.stdout).candidates[0].content).toBe('UNKNOWN'); expect(json.stdout).not.toContain('synthetic_secret');
    const text = cli([event()], ['--format', 'cloudflare-events']); expect(text.status).toBe(0); expect(text.stdout).toContain('events=1 requests=UNKNOWN security=UNKNOWN');
  });
  it('emits UNKNOWN with nonzero exit and no raw future version body', () => {
    const result = cli([{ token: 'synthetic_hidden' }], ['--format', 'cloudflare-events', '--json'], { version: 2, scope: header.scope });
    expect(result.status).toBe(1); expect(result.stderr).toBe('[ERROR] ANALYZE_INPUT_UNKNOWN\n'); expect(result.stdout).not.toContain('synthetic_hidden');
  });
  it('explains event UNKNOWN reasons in the default text report', () => {
    const result = cli([event({ observedAtMs: 999 })], ['--format', 'cloudflare-events']);
    expect(result.status).toBe(1); expect(result.stderr).toBe('[ERROR] ANALYZE_INPUT_UNKNOWN\n');
    expect(result.stdout).toContain('EVENT_OUTSIDE_PERIOD');
  });
  it('keeps sensitive200 review evidence while unknown attribution yields exit1 in JSON andtext', () => {
    const json = cli([event({ path: '/.env', attribution: 'unknown' })], ['--format', 'cloudflare-events', '--json']);
    expect(json.status).toBe(1); expect(json.stderr).toBe('[WARN] ANALYZE_INPUT_PARTIAL\n');
    const r = JSON.parse(json.stdout); expect(r.summary.inputStatus).toBe('partial'); expect(r.candidates).toHaveLength(1); expect(r.observations[0].observed.attribution).toBe('unknown');
    const text = cli([event({ path: '/.env', attribution: 'unknown' })], ['--format', 'cloudflare-events']);
    expect(text.status).toBe(1); expect(text.stdout).toContain('ATTRIBUTION_UNKNOWN'); expect(text.stdout).toContain('input_status=partial'); expect(text.stdout).not.toContain('/.env');
  });
  it.each([['--format', 'unrecognized'], ['--format', 'cloudflare-events', '--min-count', '3'], ['--format', 'cloudflare-events', '--top', '101']])('rejects format/options without silently falling back %s', (...args) => {
    const result = cli([event()], args); expect(result.status).toBe(1); expect(result.stdout).toBe(''); expect(result.stderr).toMatch(/^\[ERROR\] ANALYZE_(?:CLOUDFLARE_)?ARGUMENT_INVALID\n$/);
  });
  it('does not route ordinary monitor input through Cloudflare format by default', () => {
    const result = cli([{ event: 'block', uri: '/synthetic', status: 403 }], ['--json']); expect(result.status).toBe(1);
    const report = JSON.parse(result.stdout); expect(report.summary.parsedLines).toBe(1); expect(report.summary.unparseableLines).toBe(1); expect(report.scope).toBeUndefined();
  });
  it('emits no report or raw sensitive extra fields on a fatal parse error', () => {
    const r = cli([{ ...event(), token: 'synthetic_must_not_escape' }], ['--format', 'cloudflare-events', '--json']);
    expect(r.status).toBe(1); expect(r.stdout).toBe(''); expect(r.stderr).toBe('[ERROR] ANALYZE_CLOUDFLARE_SHAPE_INVALID\n');
  });
  it.skipIf(process.platform === 'win32')('rejects a FIFO without waiting for a writer', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-cf-fifo-'));
    try {
      const input = path.join(directory, 'fixture'); expect(spawnSync('mkfifo', [input]).status).toBe(0);
      const r = spawnSync(process.execPath, ['bin/cli.js', 'analyze', '--format', 'cloudflare-events', '--input', input], { encoding: 'utf8', timeout: 1500 });
      expect(r.error).toBeUndefined(); expect(r.status).toBe(1); expect(r.stdout).toBe(''); expect(r.stderr).toBe('[ERROR] ANALYZE_INPUT_READ_FAILED\n');
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  });
});
