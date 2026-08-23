import fs from 'node:fs';
import path from 'node:path';

import { createSecurityContract } from '../../../src/contract/security-ir';
import type { SourceAnalyzerPlugin } from '../../../src/source-analysis';

export const fakeSourceAnalyzer: SourceAnalyzerPlugin = {
  id: 'fake-typescript',
  version: '1.0.0',
  languages: ['typescript'],
  frameworks: ['fake'],
  capabilities: {
    routePaths: { status: 'supported', reason: 'Static route strings are supported.' },
    httpMethods: { status: 'supported', reason: 'Static method names are supported.' },
    routerPrefixes: { status: 'partial', reason: 'Only literal prefixes are supported.' },
    globalPrefixes: { status: 'unsupported', reason: 'Global configuration is not inspected.' },
    authentication: { status: 'partial', reason: 'Only explicit metadata is supported.' },
    authorization: { status: 'unsupported', reason: 'Role metadata is not inspected.' },
    requestContentTypes: { status: 'unsupported', reason: 'Content types are not inspected.' },
    requestLimits: { status: 'unsupported', reason: 'Body limits are not inspected.' },
    sourceLocations: { status: 'supported', reason: 'Fixture locations are deterministic.' },
    inheritedMetadata: { status: 'unsupported', reason: 'Inheritance is not inspected.' },
    dynamicExpressions: { status: 'unsupported', reason: 'Dynamic values remain unknown.' },
  },
  async analyze(context) {
    const sourceUri = context.entrypoints[0];
    const sourceBytes = fs.statSync(path.join(context.workspaceRoot, sourceUri)).size;
    return {
      contract: createSecurityContract({
        source: 'source-ast',
        capabilities: {
          routes: 'partial', parameters: 'unsupported', requestBodies: 'unsupported', authentication: 'partial',
        },
        operations: [{
          method: 'GET', path: '/health', exposure: 'unknown',
          auth: { mode: 'unknown', alternatives: [] },
          request: {
            contentTypes: [], requiredHeaders: [], queryParameters: [], pathParameters: [],
            headerParameters: [], cookieParameters: [],
          },
          provenance: [{
            source: 'source-ast', uri: sourceUri, digest: 'sha256:fixture',
            analyzer: 'fake-typescript@1.0.0', capability: 'routePaths', complete: true,
          }],
        }],
      }),
      diagnostics: [],
      metrics: {
        files: 1, totalSourceBytes: sourceBytes, largestFileBytes: sourceBytes,
        astNodes: 5, diagnostics: 0, operations: 1, maxDepth: 1,
      },
    };
  },
};
