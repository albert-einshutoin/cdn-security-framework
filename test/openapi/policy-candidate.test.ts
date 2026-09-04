import childProcess from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import * as yaml from 'js-yaml';
import { afterEach, describe, expect, test } from 'vitest';

const { validatePolicy } = require('../../validator') as typeof import('../../src/validator');

const temporaryDirectories: string[] = [];
const cli = path.join(process.cwd(), 'bin', 'cli.js');

const OPENAPI = `openapi: 3.1.0
info: { title: Candidate fixture, version: 1.0.0 }
security: [{ bearerAuth: [] }]
paths:
  /public:
    get:
      security: []
      parameters:
        - { name: X-Tenant-ID, in: header, required: true, schema: { type: string } }
        - { name: q, in: query, schema: { type: string, maxLength: 10 } }
      responses: { '200': { description: OK } }
  /items/{id}:
    post:
      parameters:
        - { name: id, in: path, required: true, schema: { type: string, maxLength: 10 } }
        - { name: X-Tenant-ID, in: header, required: true, schema: { type: string } }
        - { name: X-Write-Reason, in: header, required: true, schema: { type: string } }
        - { name: page, in: query, schema: { type: string, enum: [one, two] } }
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              properties: { name: { type: string, maxLength: 20 } }
      responses: { '204': { description: Updated } }
components:
  securitySchemes:
    bearerAuth: { type: http, scheme: bearer, bearerFormat: JWT }
`;

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

function workspace(input = OPENAPI, extension = 'yaml'): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-policy-candidate-'));
  temporaryDirectories.push(directory);
  fs.mkdirSync(path.join(directory, 'policy'));
  fs.writeFileSync(path.join(directory, `openapi.${extension}`), input);
  return directory;
}

function generate(directory: string, extra: string[] = [], extension = 'yaml') {
  return childProcess.spawnSync(process.execPath, [
    cli,
    'openapi',
    'generate-policy',
    '--input', `openapi.${extension}`,
    '--workspace-root', directory,
    '--profile', 'balanced',
    '--out', 'policy/openapi.candidate.yml',
    ...extra,
  ], { encoding: 'utf8' });
}

describe('cdn-security openapi generate-policy', () => {
  test('maps only globally faithful controls and emits review metadata', () => {
    const directory = workspace();
    const result = generate(directory);
    expect(result.status, result.stderr).toBe(0);

    const candidatePath = path.join(directory, 'policy', 'openapi.candidate.yml');
    const metadataPath = path.join(directory, 'policy', 'openapi.candidate.meta.json');
    const candidateText = fs.readFileSync(candidatePath, 'utf8');
    const policy = yaml.load(candidateText) as Record<string, unknown>;
    const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    const request = policy.request as Record<string, unknown>;
    const block = request.block as Record<string, unknown>;
    const limits = request.limits as Record<string, unknown>;

    expect(policy.routes).toBeUndefined();
    expect(request.allow_methods).toEqual(['GET', 'POST']);
    expect(block.header_missing).toEqual(['user-agent', 'x-tenant-id']);
    expect(limits).toMatchObject({
      max_query_params: 30,
      max_query_length: 1024,
      max_uri_length: 2048,
    });
    expect(candidateText).not.toMatch(/auth_gate|token_env|jwks|issuer|audience/);
    expect(metadata.appliedRecommendations.map(({ id }: { id: string }) => id)).toEqual(
      expect.arrayContaining([
        'global-allowed-methods',
        'global-required-headers',
      ]),
    );
    expect(metadata.omittedRecommendations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: 'max_query_length',
        reason: 'profile-baseline-retained-for-open-query-surface',
      }),
      expect.objectContaining({
        id: 'max_query_params',
        reason: 'profile-baseline-retained-for-open-query-surface',
      }),
      expect.objectContaining({
        id: 'max_uri_length',
        reason: 'profile-baseline-retained-for-open-query-surface',
      }),
      expect.objectContaining({ id: 'authentication' }),
      expect.objectContaining({ id: 'allowed-content-types' }),
      expect.objectContaining({ id: 'max-body-bytes' }),
      expect.objectContaining({ id: 'route-specific-required-headers' }),
      expect.objectContaining({
        id: 'route-match:/items/{id}',
        reason: 'path-template-not-representable-by-static-prefix',
      }),
    ]));
    expect(metadata.capabilityFindings).toEqual(expect.any(Array));
    expect(JSON.stringify(metadata)).not.toContain(directory);
    expect(metadata).not.toHaveProperty('generatedAt');
    expect(validatePolicy({ policy, pkgRoot: process.cwd() }).ok).toBe(true);

    const before = [candidatePath, metadataPath].map((file) => fs.readFileSync(file, 'utf8'));
    expect(generate(directory).status).toBe(1);
    expect(generate(directory, ['--force']).status).toBe(0);
    expect([candidatePath, metadataPath].map((file) => fs.readFileSync(file, 'utf8'))).toEqual(before);

    const dist = path.join(directory, 'dist-candidate');
    childProcess.execFileSync(process.execPath, [
      cli, 'build', '--policy', candidatePath, '--out-dir', dist,
    ], { cwd: directory, encoding: 'utf8' });
    expect(fs.existsSync(path.join(dist, 'edge', 'viewer-request.js'))).toBe(true);
  });

  test('keeps normalized candidate order deterministic while retaining raw source digest', () => {
    const firstDocument = JSON.stringify({
      openapi: '3.1.0', info: { title: 'Order', version: '1' }, paths: {
        '/b': { post: { responses: { 204: { description: 'ok' } } } },
        '/a': { get: { responses: { 200: { description: 'ok' } } } },
      },
    });
    const secondDocument = JSON.stringify({
      paths: {
        '/a': { get: { responses: { 200: { description: 'ok' } } } },
        '/b': { post: { responses: { 204: { description: 'ok' } } } },
      }, info: { version: '1', title: 'Order' }, openapi: '3.1.0',
    });
    const first = workspace(firstDocument, 'json');
    const second = workspace(secondDocument, 'json');
    expect(generate(first, [], 'json').status).toBe(0);
    expect(generate(second, [], 'json').status).toBe(0);

    const candidate = (directory: string) => fs.readFileSync(
      path.join(directory, 'policy', 'openapi.candidate.yml'), 'utf8',
    );
    const metadata = (directory: string) => JSON.parse(fs.readFileSync(
      path.join(directory, 'policy', 'openapi.candidate.meta.json'), 'utf8',
    ));
    expect(candidate(first)).toBe(candidate(second));
    const firstMetadata = metadata(first);
    const secondMetadata = metadata(second);
    expect(firstMetadata.sourceDigest).not.toBe(secondMetadata.sourceDigest);
    expect(firstMetadata.irDigest).toBe(secondMetadata.irDigest);
    delete firstMetadata.sourceDigest;
    delete secondMetadata.sourceDigest;
    expect(firstMetadata).toEqual(secondMetadata);
  });

  test('retains profile limits when a recommendation is not a safe finite upper bound', () => {
    const directory = workspace(`openapi: 3.1.0
info: { title: Unbounded, version: 1.0.0 }
paths:
  /search:
    get:
      parameters:
        - { name: q, in: query, schema: { type: string } }
      responses: { '200': { description: OK } }
`);
    const result = childProcess.spawnSync(process.execPath, [
      cli, 'openapi', 'generate-policy', '--input', 'openapi.yaml',
      '--workspace-root', directory, '--profile', 'strict',
      '--out', 'policy/openapi.candidate.yml',
    ], { encoding: 'utf8' });
    expect(result.status, result.stderr).toBe(0);
    const policy = yaml.load(fs.readFileSync(
      path.join(directory, 'policy', 'openapi.candidate.yml'), 'utf8',
    )) as { request: { limits: Record<string, number> } };
    expect(policy.request.limits.max_query_length).toBe(512);
    const metadata = JSON.parse(fs.readFileSync(
      path.join(directory, 'policy', 'openapi.candidate.meta.json'), 'utf8',
    ));
    expect(metadata.omittedRecommendations).toContainEqual(expect.objectContaining({
      id: 'max_query_length',
      reason: 'recommendation-is-partial-unknown-or-unbounded',
    }));
  });

  test('rejects active policy, source aliases, invalid profiles, and unsafe existing outputs', () => {
    const directory = workspace();
    const run = (args: string[]) => childProcess.spawnSync(process.execPath, [cli, ...args], {
      encoding: 'utf8',
    });
    const common = [
      'openapi', 'generate-policy', '--input', 'openapi.yaml',
      '--workspace-root', directory, '--profile', 'balanced',
    ];

    const active = run([...common, '--out', 'policy/security.yml', '--force']);
    expect(active.status).toBe(1);
    expect(active.stderr).toContain('OPENAPI_CANDIDATE_OUTPUT_PROTECTED');
    const activeCaseVariant = run([...common, '--out', 'policy/SECURITY.YML', '--force']);
    expect(activeCaseVariant.status).toBe(1);
    expect(activeCaseVariant.stderr).toContain('OPENAPI_CANDIDATE_OUTPUT_PROTECTED');

    const activePolicy = path.join(directory, 'policy', 'security.yml');
    fs.writeFileSync(activePolicy, 'active-policy');
    fs.linkSync(activePolicy, path.join(directory, 'policy', 'security-alias.yml'));
    const activeAlias = run([...common, '--out', 'policy/security-alias.yml', '--force']);
    expect(activeAlias.status).toBe(1);
    expect(activeAlias.stderr).toContain('OPENAPI_CANDIDATE_OUTPUT_PROTECTED');
    expect(fs.readFileSync(activePolicy, 'utf8')).toBe('active-policy');

    const sourceAlias = path.join(directory, 'openapi-alias.yaml');
    fs.linkSync(path.join(directory, 'openapi.yaml'), sourceAlias);
    const alias = run([...common, '--out', 'openapi-alias.yaml', '--force']);
    expect(alias.status).toBe(1);
    expect(alias.stderr).toContain('OPENAPI_CANDIDATE_OUTPUT_PROTECTED');

    const invalidProfile = run([
      'openapi', 'generate-policy', '--input', 'openapi.yaml', '--workspace-root', directory,
      '--profile', 'custom', '--out', 'policy/custom.yml',
    ]);
    expect(invalidProfile.status).toBe(1);
    expect(invalidProfile.stderr).toContain('OPENAPI_CANDIDATE_INVALID_PROFILE');

    fs.symlinkSync('openapi.yaml', path.join(directory, 'policy', 'linked.yml'));
    const linked = run([...common, '--out', 'policy/linked.yml', '--force']);
    expect(linked.status).toBe(1);
    expect(linked.stderr).toContain('OPENAPI_CANDIDATE_OUTPUT_PROTECTED');

    const protectedTarget = path.join(directory, 'protected-profiles');
    fs.mkdirSync(protectedTarget);
    fs.symlinkSync('../protected-profiles', path.join(directory, 'policy', 'profiles'));
    const protectedDirectoryAlias = run([
      ...common, '--out', 'policy/profiles/strict.yml', '--force',
    ]);
    expect(protectedDirectoryAlias.status).toBe(1);
    expect(protectedDirectoryAlias.stderr).toContain('OPENAPI_CANDIDATE_OUTPUT_PROTECTED');
  });
});
