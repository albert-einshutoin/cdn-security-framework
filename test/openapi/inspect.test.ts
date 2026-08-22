import childProcess from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import Ajv from 'ajv';
import { afterEach, describe, expect, test } from 'vitest';

import {
  formatOpenApiInspectionJson,
  formatOpenApiInspectionText,
  inspectOpenApi,
} from '../../src/openapi/inspect';
import { fixtureRoot } from '../helpers/fixture-root';

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('inspectOpenApi', () => {
  test('returns deterministic, schema-valid Security IR without raw source metadata', () => {
    const report = inspectOpenApi({
      inputPath: 'valid/openapi-3.0.yaml',
      workspaceRoot: fixtureRoot,
    });
    const json = formatOpenApiInspectionJson(report);
    const securitySchema = JSON.parse(fs.readFileSync(
      path.join(process.cwd(), 'schemas/security-ir-v1.schema.json'),
      'utf8',
    ));
    const reportSchema = JSON.parse(fs.readFileSync(
      path.join(process.cwd(), 'schemas/openapi-inspection-v1.schema.json'),
      'utf8',
    ));
    const validate = new Ajv({ allErrors: true }).addSchema(securitySchema).compile(reportSchema);

    expect(validate(JSON.parse(json)), JSON.stringify(validate.errors)).toBe(true);
    expect(report).toMatchObject({
      schemaVersion: 1,
      analyzer: {
        name: 'cdn-security-openapi-inspect',
        version: 1,
        openapiVersion: '3.0',
      },
      summary: {
        operationCount: 2,
        exposures: { public: 1, authenticated: 1, privileged: 0, unknown: 0 },
      },
      capabilities: { requestBodies: 'partial' },
    });
    expect(report.contract.operations.map(({ routeKey }) => routeKey)).toEqual([
      'GET /public',
      'POST /users/{userId}',
    ]);
    expect(formatOpenApiInspectionJson(inspectOpenApi({
      inputPath: 'valid/openapi-3.1.json',
      workspaceRoot: fixtureRoot,
    }))).toBe(fs.readFileSync(
      path.join(fixtureRoot, 'expected/openapi-inspection-3.1.json'),
      'utf8',
    ));
    expect(json).not.toMatch(/generatedAt|rawOpenApi|\/private\/|\\Users\\/);
    expect(formatOpenApiInspectionJson(inspectOpenApi({
      inputPath: 'valid/openapi-3.0.yaml',
      workspaceRoot: fixtureRoot,
    }))).toBe(json);
  });

  test('formats capability, exposure, route, content-type, and parameter summaries', () => {
    const report = inspectOpenApi({
      inputPath: 'valid/openapi-3.0.yaml',
      workspaceRoot: fixtureRoot,
    });
    const text = formatOpenApiInspectionText(report);

    expect(text).toContain('OpenAPI version: 3.0');
    expect(text).toContain('Operations: 2');
    expect(text).toContain('Exposure: public=1 authenticated=1 privileged=0 unknown=0');
    expect(text).toContain('requestBodies=partial');
    expect(text).toContain('GET /public exposure=public auth=none content-types=- parameters=0');
    expect(text).toContain('POST /users/{userId} exposure=authenticated auth=alternatives');
    expect(text).toContain('content-types=application/json,application/x-www-form-urlencoded,multipart/form-data,text/plain');
    expect(text).toContain('parameters=4');

    report.contract.operations[0].routeKey += '\u001b[31m';
    report.contract.operations[0].request.contentTypes.push('text/plain\u202e');
    const escapedText = formatOpenApiInspectionText(report);
    expect(escapedText).not.toContain('\u001b');
    expect(escapedText).not.toContain('\u202e');
    expect(escapedText).toContain('\\u{001b}');
    expect(escapedText).toContain('text/plain\\u{202e}');
  });

  test('reports configured limits only when usage is near them', () => {
    const report = inspectOpenApi({
      inputPath: 'valid/openapi-3.1.json',
      workspaceRoot: fixtureRoot,
      limits: { maxOperations: 1 },
    });

    expect(report.diagnostics).toContainEqual({
      code: 'OPENAPI_LIMIT_NEAR',
      level: 'warning',
      message: 'OpenAPI analysis usage is near the configured limit.',
      metric: 'operations',
      used: 1,
      limit: 1,
    });
  });
});

describe('cdn-security openapi inspect', () => {
  test('prints JSON and writes only an explicitly selected report path', () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-inspect-cli-'));
    temporaryDirectories.push(workspace);
    const input = path.join(workspace, 'openapi.json');
    const policy = path.join(workspace, 'policy', 'security.yml');
    const distSentinel = path.join(workspace, 'dist', 'sentinel.txt');
    fs.mkdirSync(path.dirname(policy), { recursive: true });
    fs.mkdirSync(path.dirname(distSentinel), { recursive: true });
    fs.writeFileSync(input, JSON.stringify({ openapi: '3.1.0', paths: {} }));
    fs.writeFileSync(policy, 'version: 1\n');
    fs.writeFileSync(distSentinel, 'keep');
    const before = [input, policy, distSentinel].map((file) => fs.readFileSync(file, 'utf8'));
    const cli = path.join(process.cwd(), 'bin', 'cli.js');
    const args = ['openapi', 'inspect', '--input', 'openapi.json', '--workspace-root', workspace, '--json'];

    const stdout = childProcess.execFileSync(process.execPath, [cli, ...args], {
      encoding: 'utf8',
    });
    expect(JSON.parse(stdout)).toMatchObject({
      schemaVersion: 1,
      analyzer: { openapiVersion: '3.1' },
      summary: { operationCount: 0 },
    });

    const reportPath = path.join(workspace, 'report.json');
    childProcess.execFileSync(process.execPath, [cli, ...args, '--out', 'report.json']);
    expect(JSON.parse(fs.readFileSync(reportPath, 'utf8'))).toEqual(JSON.parse(stdout));
    expect(childProcess.spawnSync(
      process.execPath,
      [cli, ...args, '--out', 'report.json'],
      { encoding: 'utf8' },
    ).status).toBe(1);
    childProcess.execFileSync(process.execPath, [cli, ...args, '--out', 'report.json', '--force']);
    expect([input, policy, distSentinel].map((file) => fs.readFileSync(file, 'utf8'))).toEqual(before);

    const inputAlias = path.join(workspace, 'input-alias.json');
    fs.linkSync(input, inputAlias);
    const hardLinkOutput = childProcess.spawnSync(
      process.execPath,
      [cli, ...args, '--out', 'input-alias.json', '--force'],
      { encoding: 'utf8' },
    );
    expect(hardLinkOutput.status).toBe(1);
    expect(hardLinkOutput.stderr).toContain('OPENAPI_OUTPUT_PROTECTED');
    expect(fs.readFileSync(input, 'utf8')).toBe(before[0]);
  });

  test('returns stable safe errors for invalid input and unsafe output paths', () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-inspect-error-'));
    temporaryDirectories.push(workspace);
    const cli = path.join(process.cwd(), 'bin', 'cli.js');
    const run = (args: string[]) => childProcess.spawnSync(process.execPath, [cli, ...args], {
      encoding: 'utf8',
    });

    const missing = run([
      'openapi', 'inspect', '--input', 'missing.yaml', '--workspace-root', workspace, '--json',
    ]);
    expect(missing.status).toBe(1);
    expect(missing.stdout).toBe('');
    expect(missing.stderr).toContain('OPENAPI_INPUT_NOT_FOUND');

    fs.writeFileSync(path.join(workspace, 'openapi.json'), JSON.stringify({ openapi: '3.1.0', paths: {} }));
    const missingParent = run([
      'openapi', 'inspect', '--input', 'openapi.json', '--workspace-root', workspace,
      '--json', '--out', 'missing/report.json',
    ]);
    expect(missingParent.status).toBe(1);
    expect(missingParent.stderr).toContain('OPENAPI_OUTPUT_PARENT_NOT_FOUND');

    const protectedOutput = run([
      'openapi', 'inspect', '--input', 'openapi.json', '--workspace-root', workspace,
      '--json', '--out', 'dist/report.json',
    ]);
    expect(protectedOutput.status).toBe(1);
    expect(protectedOutput.stderr).toContain('OPENAPI_OUTPUT_PROTECTED');
  });
});
