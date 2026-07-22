import { readFileSync } from 'node:fs';
import path from 'node:path';

import Ajv, { type AnySchema } from 'ajv';

import type { ChangedFile, DetectedProject } from './core';

export type AnalysisStrategy = 'selective' | 'full' | 'failure';

export interface AnalysisResult {
  schemaVersion: 1;
  strategy: AnalysisStrategy;
  baseRevision: string;
  headRevision: string;
  changedFiles: ChangedFile[];
  detectedProjects: DetectedProject[];
  affectedProjects: string[];
  affectedModules: string[];
  unitTestTargets: string[];
  integrationTestTargets: string[];
  e2eTestTargets: string[];
  smokeTestTargets: string[];
  fallback: boolean;
  fallbackReason: string | null;
  diagnostics: string[];
  executionPlan: string[];
  requiresPackageMatrix: boolean;
  selectedTestTargetCount: number;
  availableTestTargetCount: number;
}

export function validateAnalysisResult(repositoryRoot: string, result: AnalysisResult): void {
  const schemaPath = path.join(repositoryRoot, 'ci', 'impact', 'schema', 'result.schema.json');
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as AnySchema;
  const validate = new Ajv({ allErrors: true, strict: true }).compile(schema);
  if (!validate(result)) {
    const details = validate.errors
      ?.map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`)
      .join('; ');
    throw new Error(`impact result does not match its schema: ${details ?? 'unknown error'}`);
  }
}
