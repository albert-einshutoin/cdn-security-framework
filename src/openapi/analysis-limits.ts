import { OpenApiAnalysisError } from './analysis-error';

export interface OpenApiAnalysisLimits {
  maxDocumentBytes: number;
  maxResolvedDocuments: number;
  maxRefDepth: number;
  maxSchemaDepth: number;
  maxNodes: number;
  maxOperations: number;
  maxParametersPerOperation: number;
  maxSecuritySchemes: number;
  maxYamlAliases: number;
  maxStringLength: number;
  timeoutMs: number;
}

export type OpenApiAnalysisLimitName = keyof OpenApiAnalysisLimits;

export const OPENAPI_ANALYSIS_LIMIT_RANGES: Readonly<
  Record<OpenApiAnalysisLimitName, Readonly<{ min: number; max: number }>>
> = Object.freeze({
  maxDocumentBytes: Object.freeze({ min: 1, max: 4 * 1024 * 1024 }),
  maxResolvedDocuments: Object.freeze({ min: 1, max: 64 }),
  maxRefDepth: Object.freeze({ min: 1, max: 128 }),
  maxSchemaDepth: Object.freeze({ min: 1, max: 256 }),
  maxNodes: Object.freeze({ min: 1, max: 1_000_000 }),
  maxOperations: Object.freeze({ min: 1, max: 10_000 }),
  maxParametersPerOperation: Object.freeze({ min: 1, max: 500 }),
  maxSecuritySchemes: Object.freeze({ min: 1, max: 256 }),
  maxYamlAliases: Object.freeze({ min: 1, max: 1_000 }),
  maxStringLength: Object.freeze({ min: 1, max: 1024 * 1024 }),
  timeoutMs: Object.freeze({ min: 1, max: 60_000 }),
});

export const DEFAULT_OPENAPI_ANALYSIS_LIMITS: Readonly<OpenApiAnalysisLimits> = Object.freeze({
  maxDocumentBytes: 2 * 1024 * 1024,
  maxResolvedDocuments: 32,
  maxRefDepth: 32,
  maxSchemaDepth: 64,
  maxNodes: 250_000,
  maxOperations: 2_000,
  maxParametersPerOperation: 100,
  maxSecuritySchemes: 64,
  maxYamlAliases: 100,
  maxStringLength: 64 * 1024,
  timeoutMs: 10_000,
});

const LIMIT_NAMES = Object.freeze(
  Object.keys(OPENAPI_ANALYSIS_LIMIT_RANGES) as OpenApiAnalysisLimitName[],
);

export function validateOpenApiAnalysisLimits(input: unknown): Readonly<OpenApiAnalysisLimits> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new OpenApiAnalysisError('OPENAPI_INVALID_LIMITS');
  }
  const record = input as Record<string, unknown>;
  if (Object.keys(record).length !== LIMIT_NAMES.length
    || Object.keys(record).some((key) => !LIMIT_NAMES.includes(key as OpenApiAnalysisLimitName))) {
    throw new OpenApiAnalysisError('OPENAPI_INVALID_LIMITS');
  }

  const validated = {} as OpenApiAnalysisLimits;
  for (const name of LIMIT_NAMES) {
    const value = record[name];
    const range = OPENAPI_ANALYSIS_LIMIT_RANGES[name];
    if (!Number.isInteger(value) || (value as number) < range.min || (value as number) > range.max) {
      throw new OpenApiAnalysisError('OPENAPI_INVALID_LIMITS', {
        pointer: `/limits/${name}`,
      });
    }
    validated[name] = value as number;
  }
  return Object.freeze(validated);
}
