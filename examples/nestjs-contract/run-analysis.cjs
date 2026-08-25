#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const { createHash } = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const yaml = require('js-yaml');

const {
  compareSourceOpenApiContracts,
  compareSourcePolicyContracts,
  projectPolicyToAllowedSurface,
} = require('cdn-security-framework/contract');
const { DEFAULT_SOURCE_ANALYSIS_LIMITS, runSourceAnalyzer } = require('cdn-security-framework/source-analysis');
const { createNestJsSourceAnalyzer } = require('cdn-security-framework/source/nestjs');
const {
  DEFAULT_OPENAPI_ANALYSIS_LIMITS,
  loadOpenApiDocument,
  normalizeOpenApiOperations,
  resolveOpenApiReferences,
} = require('cdn-security-framework/openapi');
const { parsePolicyFile } = require('cdn-security-framework/parser');

function contractEvidence(contract, metadata) {
  return {
    ...metadata,
    digest: semanticDigest(contract),
    complete: contract.capabilities.routes === 'complete',
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}

function semanticDigest(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function findingSummary(finding) {
  return {
    ruleId: finding.ruleId,
    severity: finding.severity,
    confidence: finding.confidence,
    ...(finding.route ? { route: finding.route } : {}),
    evidence: finding.evidence,
  };
}

function readBounded(sourceRoot, source, relative, remainingBytes) {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const descriptor = fs.openSync(source, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = fs.fstatSync(descriptor);
    const currentPath = fs.realpathSync(source);
    const current = fs.statSync(currentPath);
    const withinRoot = path.relative(sourceRoot, currentPath);
    if (!withinRoot || withinRoot.startsWith(`..${path.sep}`) || path.isAbsolute(withinRoot)
      || !opened.isFile() || opened.dev !== current.dev || opened.ino !== current.ino) {
      throw new Error(`fixture file changed or escaped input root: ${relative}`);
    }
    if (opened.size > DEFAULT_SOURCE_ANALYSIS_LIMITS.maxFileBytes || opened.size > remainingBytes) {
      throw new Error(`fixture file exceeds source analysis byte limit: ${relative}`);
    }
    const contents = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < contents.byteLength) {
      const read = fs.readSync(descriptor, contents, offset, contents.byteLength - offset, null);
      if (read === 0) throw new Error(`fixture file changed while reading: ${relative}`);
      offset += read;
    }
    if (fs.readSync(descriptor, Buffer.alloc(1), 0, 1, null) !== 0) {
      throw new Error(`fixture file changed while reading: ${relative}`);
    }
    return contents;
  } finally {
    fs.closeSync(descriptor);
  }
}

const FIXTURE_FILES = [
  'tsconfig.json',
  'tsconfig.base.json',
  'openapi.yaml',
  'security-analyzer.yml',
  'policy/security.yml',
  'packages/shared/tsconfig.json',
  'src/base.controller.ts',
  'src/decorators.ts',
  'src/guards.ts',
  'src/runtime-prefix.ts',
  'src/users.controller.ts',
  'stubs/nestjs-common/index.d.ts',
  'stubs/nestjs-common/index.js',
  'stubs/nestjs-common/package.json',
];

function copyFixture(sourceRoot, targetRoot) {
  if (FIXTURE_FILES.length > DEFAULT_SOURCE_ANALYSIS_LIMITS.maxFiles) {
    throw new Error('fixture exceeds source analysis file limit');
  }
  let totalBytes = 0;
  for (const relative of FIXTURE_FILES) {
    const requested = path.join(sourceRoot, relative);
    if (fs.lstatSync(requested).isSymbolicLink()) throw new Error(`fixture file must not be a symlink: ${relative}`);
    const source = fs.realpathSync(requested);
    const withinRoot = path.relative(sourceRoot, source);
    if (!withinRoot || withinRoot.startsWith(`..${path.sep}`) || path.isAbsolute(withinRoot)) {
      throw new Error(`fixture file is outside input root: ${relative}`);
    }
    const contents = readBounded(
      sourceRoot,
      source,
      relative,
      DEFAULT_SOURCE_ANALYSIS_LIMITS.maxTotalSourceBytes - totalBytes,
    );
    totalBytes += contents.byteLength;
    const target = path.join(targetRoot, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, contents);
  }
}

async function analyzeExample(inputRoot = __dirname) {
  const sourceRoot = fs.realpathSync(inputRoot);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nestjs-contract-analysis-'));
  try {
    copyFixture(sourceRoot, root);
    const stub = path.join(root, 'stubs/nestjs-common');
    const installedStub = path.join(root, 'node_modules/@nestjs/common');
    fs.mkdirSync(path.dirname(installedStub), { recursive: true });
    fs.cpSync(stub, installedStub, { recursive: true });

    const config = yaml.load(fs.readFileSync(path.join(root, 'security-analyzer.yml'), 'utf8'));
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(config), {
      workspaceRoot: root,
      entrypoints: ['tsconfig.json'],
      limits: DEFAULT_SOURCE_ANALYSIS_LIMITS,
      logger: { log() {} },
    });
    if (execution.status !== 'success') throw new Error(execution.diagnostics[0]?.safeMessage ?? 'source analysis failed');

    const openApiRoot = loadOpenApiDocument({ inputPath: path.join(root, 'openapi.yaml'), workspaceRoot: root });
    const declared = normalizeOpenApiOperations(resolveOpenApiReferences({
      root: openApiRoot, workspaceRoot: root, limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    }));
    const parsed = parsePolicyFile({ policyPath: path.join(root, 'policy/security.yml') });
    if (!parsed.ok || !parsed.policy) throw new Error(parsed.errors.join('\n') || 'policy parse failed');

    const implementedEvidence = contractEvidence(execution.result.contract, {
      source: 'source-ast', uri: 'tsconfig.json',
      analyzer: 'nestjs@1', capability: 'nestjs-routes-v1',
    });
    const declaredEvidence = contractEvidence(declared, {
      source: 'openapi', uri: 'openapi.yaml',
      analyzer: 'openapi@1', capability: 'openapi-operations-v1',
    });
    const sourceOpenApi = compareSourceOpenApiContracts({
    declared, implemented: execution.result.contract, declaredEvidence, implementedEvidence,
  });
    const sourcePolicy = compareSourcePolicyContracts({
    implemented: execution.result.contract,
    implementedEvidence,
    allowed: projectPolicyToAllowedSurface(parsed.policy, {
      policyDigest: semanticDigest(parsed.policy), sourceUri: 'policy/security.yml',
    }),
    target: 'aws',
  });
    return {
      schemaVersion: 1,
      operations: execution.result.contract.operations.map(({ routeKey, exposure, auth }) => ({
        routeKey, exposure, authMode: auth.mode,
      })),
      diagnostics: execution.result.diagnostics.map(({ code }) => code),
      sourceOpenApi: sourceOpenApi.map(findingSummary),
      sourcePolicy: sourcePolicy.map(findingSummary),
    };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

module.exports = { analyzeExample };

if (require.main === module) {
  const root = process.argv[2] ? path.resolve(process.argv[2]) : undefined;
  analyzeExample(root).then((report) => console.log(JSON.stringify(report, null, 2))).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
