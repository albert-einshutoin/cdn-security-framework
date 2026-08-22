import path from 'node:path';

export const OPENAPI_ANALYSIS_ERROR_CODES = [
  'OPENAPI_INPUT_NOT_FOUND',
  'OPENAPI_DOCUMENT_TOO_LARGE',
  'OPENAPI_PARSE_ERROR',
  'OPENAPI_INVALID_ROOT',
  'OPENAPI_UNSUPPORTED_VERSION',
  'OPENAPI_YAML_ALIAS_LIMIT',
  'OPENAPI_REF_OUTSIDE_ROOT',
  'OPENAPI_REMOTE_REF_DISABLED',
  'OPENAPI_REF_CYCLE_LIMIT',
  'OPENAPI_NODE_LIMIT',
  'OPENAPI_INVALID_LIMITS',
] as const;

export type OpenApiAnalysisErrorCode = typeof OPENAPI_ANALYSIS_ERROR_CODES[number];

const SAFE_MESSAGES: Record<OpenApiAnalysisErrorCode, string> = {
  OPENAPI_INPUT_NOT_FOUND: 'OpenAPI input was not found.',
  OPENAPI_DOCUMENT_TOO_LARGE: 'OpenAPI document exceeds the configured size limit.',
  OPENAPI_PARSE_ERROR: 'OpenAPI document could not be parsed.',
  OPENAPI_INVALID_ROOT: 'OpenAPI document root is invalid.',
  OPENAPI_UNSUPPORTED_VERSION: 'OpenAPI version is not supported.',
  OPENAPI_YAML_ALIAS_LIMIT: 'OpenAPI YAML alias limit was exceeded.',
  OPENAPI_REF_OUTSIDE_ROOT: 'OpenAPI reference is outside the workspace root.',
  OPENAPI_REMOTE_REF_DISABLED: 'Remote OpenAPI references are disabled.',
  OPENAPI_REF_CYCLE_LIMIT: 'OpenAPI reference cycle or depth limit was exceeded.',
  OPENAPI_NODE_LIMIT: 'OpenAPI analysis node limit was exceeded.',
  OPENAPI_INVALID_LIMITS: 'OpenAPI analysis limits are invalid.',
};

export interface OpenApiAnalysisErrorOptions {
  sourceUri?: string;
  pointer?: string;
  line?: number;
  column?: number;
}

function safeSourceUri(sourceUri: string | undefined): string | undefined {
  if (!sourceUri) return undefined;
  let withoutQuery = sourceUri.split(/[?#]/, 1)[0].replace(/\\/g, '/');
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(sourceUri)) {
    try {
      withoutQuery = new URL(sourceUri).pathname;
    } catch {
      return undefined;
    }
  }
  const filename = path.posix.basename(withoutQuery).replace(/[\u0000-\u001f\u007f]/g, '');
  return filename.slice(0, 255) || undefined;
}

function safePointer(pointer: string | undefined): string | undefined {
  if (!pointer) return undefined;
  const cleaned = pointer
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/\?.*$/, '')
    .replace(/(authorization|cookie|set[-_]?cookie|api[_-]?key|token|secret|password)\s*[:=]\s*[^/]+/gi, '$1=[REDACTED]')
    .replace(/\bBearer\s+[^/]+/gi, 'Bearer [REDACTED]');
  return cleaned.slice(0, 1_024) || undefined;
}

export class OpenApiAnalysisError extends Error {
  readonly safeMessage: string;
  readonly sourceUri?: string;
  readonly pointer?: string;
  readonly line?: number;
  readonly column?: number;

  constructor(
    readonly code: OpenApiAnalysisErrorCode,
    options: OpenApiAnalysisErrorOptions = {},
  ) {
    const safeMessage = SAFE_MESSAGES[code];
    super(safeMessage);
    this.name = 'OpenApiAnalysisError';
    this.safeMessage = safeMessage;
    this.sourceUri = safeSourceUri(options.sourceUri);
    this.pointer = safePointer(options.pointer);
    this.line = Number.isInteger(options.line) && (options.line as number) > 0
      ? options.line
      : undefined;
    this.column = Number.isInteger(options.column) && (options.column as number) > 0
      ? options.column
      : undefined;
  }

  toJSON(): Record<string, string | number> {
    return {
      code: this.code,
      safeMessage: this.safeMessage,
      ...(this.sourceUri ? { sourceUri: this.sourceUri } : {}),
      ...(this.pointer ? { pointer: this.pointer } : {}),
      ...(this.line ? { line: this.line } : {}),
      ...(this.column ? { column: this.column } : {}),
    };
  }
}
