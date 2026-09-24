export const SENSITIVE_KEY_PATTERN = /(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|api[-_]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|token|secret|password)/i;

export function isSensitiveField(key: string, value: unknown): boolean {
  if (SENSITIVE_KEY_PATTERN.test(key)) return true;
  if (!/^credentials?$/i.test(key)) return false;
  // Authentication findings carry a descriptor, never the credential value.
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return true;
  const descriptor = value as Record<string, unknown>;
  return Object.keys(descriptor).length !== 2
    || !Object.prototype.hasOwnProperty.call(descriptor, 'location')
    || !Object.prototype.hasOwnProperty.call(descriptor, 'names')
    || (descriptor.location !== 'header' && descriptor.location !== 'query')
    || !Array.isArray(descriptor.names)
    || !descriptor.names.every((name) => typeof name === 'string');
}

const AUTH_SCHEME_PREFIX = /\b(?:Basic|Bearer|Digest|Negotiate|AWS4-HMAC-SHA256|Hawk|Signature)\s+/gi;
const ASSIGNMENT_PREFIX = /(?<![?&])["']?\b(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x-api-key|api[-_]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|credentials?|token|password|secret)\b["']?\s*[:=]\s*["']?/gi;
const QUERY_PREFIX = /[?&][^=\s&#]+=/g;
const PROVIDER_TOKEN_PATTERN = /\b(?:sk-(?:proj-)?|gh[opsur]_|github_pat_|AKIA|(?:sk|pk)_)[A-Za-z0-9_.-]{8,}/i;
const REDACTED_MARKER = '[REDACTED]';
const SENSITIVE_FILENAME_KEY = '(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|(?:x[-_])?api[-_]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|credentials?|token|password|secret)';
// A qualified `-token-value` is ambiguous with a document name; evidence must fail closed.
const SENSITIVE_FILENAME_MARKER = new RegExp(`(?:^${SENSITIVE_FILENAME_KEY}[_=-].+|(?:^|[._-])${SENSITIVE_FILENAME_KEY}[=._-].+)`, 'i');

export function redactEvidenceFilename(uri: string): string {
  return uri.split('/').map((segment) => {
    let decoded = segment;
    for (let depth = 0; depth < 3; depth += 1) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch { break; }
    }
    const encodedAgain = /%[0-9A-Fa-f]{2}/.test(decoded);
    return encodedAgain || decoded.split('/').some((part) => SENSITIVE_FILENAME_MARKER.test(part))
      ? '[REDACTED_FILENAME]' : segment;
  }).join('/');
}

function isJsonContinuation(value: string): boolean {
  const suffix = value.trimStart();
  if (!suffix.startsWith(',') && !suffix.startsWith('}')) return false;
  try {
    JSON.parse(`{"__redacted__":"value"${suffix}`);
    return true;
  } catch {
    const normalized = suffix.replace(/'((?:\\.|[^'\\\r\n])*)'/g, (_match, content: string) => (
      JSON.stringify(content.replace(/\\'/g, "'"))
    ));
    try {
      JSON.parse(`{"__redacted__":"value"${normalized}`);
      return true;
    } catch {
      return false;
    }
  }
}

function isSafeLineContinuation(value: string): boolean {
  if (!/[\r\n]/u.test(value) || /(?:\r\n|\r|\n)[ \t]/u.test(value)) return false;
  return value.split(/\r\n|\r|\n/u).every((line) => !hasUnsafeSensitiveText(line));
}

function isCompleteRedactedValue(
  value: string,
  markerEnd: number,
  query: boolean,
  allowJsonContinuation = false,
): boolean {
  let index = markerEnd;
  while (index < value.length && /["'}\]]/u.test(value[index] ?? '')) index += 1;
  const separatorStart = index;
  if (allowJsonContinuation && isJsonContinuation(value.slice(separatorStart))) return true;
  let separatorConsumed = false;
  while (index < value.length && /[,;#]/u.test(value[index] ?? '')) {
    separatorConsumed = true;
    index += 1;
  }
  if (index >= value.length) return true;
  if (separatorConsumed) {
    const suffix = value.slice(index);
    return /^\s*$/u.test(suffix) || isSafeLineContinuation(value.slice(separatorStart));
  }
  if (/\s/u.test(value[index] ?? '')) {
    return /^\s*$/u.test(value.slice(index)) || isSafeLineContinuation(value.slice(separatorStart));
  }
  return query && value[index] === '&' && /^[^=\s&#]+=/.test(value.slice(index + 1));
}

function hasUnsafeSensitiveValue(value: string, prefix: RegExp, query: boolean): boolean {
  for (const match of value.matchAll(prefix)) {
    const markerStart = (match.index ?? 0) + match[0].length;
    if (!value.startsWith(REDACTED_MARKER, markerStart)
      || !isCompleteRedactedValue(value, markerStart + REDACTED_MARKER.length, query)) {
      return true;
    }
  }
  return false;
}

function hasUnsafeAssignmentValue(value: string): boolean {
  for (const match of value.matchAll(ASSIGNMENT_PREFIX)) {
    const markerStart = (match.index ?? 0) + match[0].length;
    if (value.startsWith(REDACTED_MARKER, markerStart)
      && isCompleteRedactedValue(value, markerStart + REDACTED_MARKER.length, false, true)) {
      continue;
    }
    const scheme = /^(?:Basic|Bearer|Digest|Negotiate|AWS4-HMAC-SHA256|Hawk|Signature)\s+/i
      .exec(value.slice(markerStart));
    if (scheme && value.startsWith(REDACTED_MARKER, markerStart + scheme[0].length)
      && isCompleteRedactedValue(value, markerStart + scheme[0].length + REDACTED_MARKER.length, false)) {
      continue;
    }
    return true;
  }
  return false;
}

export function hasUnsafeSensitiveText(value: string): boolean {
  return hasUnsafeSensitiveValue(value, AUTH_SCHEME_PREFIX, false)
    || hasUnsafeAssignmentValue(value)
    || hasUnsafeSensitiveValue(value, QUERY_PREFIX, true)
    || PROVIDER_TOKEN_PATTERN.test(value);
}

export function redactSensitiveText(value: string): string {
  return value
    .replace(/(\b[A-Za-z][A-Za-z0-9+.-]*:\/\/)[^\/?#\s]*@/g, '$1')
    .replace(/([?&][^=\s&#]+)=([^&#\s]*)/g, '$1=[REDACTED]')
    .replace(/(["'](?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|credentials?|token|password|secret)["']\s*:\s*)((?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^,}\r\n]*))/gi, (_match, prefix: string, rawValue: string) => {
      const quote = rawValue.startsWith("'") ? "'" : '"';
      return `${prefix}${quote}[REDACTED]${quote}`;
    })
    .replace(/\b(authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|credentials?|token|password|secret)\s*[:=]\s*[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*/gi, '$1=[REDACTED]')
    .replace(/\b(Basic|Bearer|Digest|Negotiate|AWS4-HMAC-SHA256|Hawk|Signature)\s+[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*/gi, '$1 [REDACTED]')
    .replace(/\b(?:sk-(?:proj-)?|gh[opsur]_|github_pat_|AKIA|(?:sk|pk)_)[A-Za-z0-9_.-]{8,}/gi, REDACTED_MARKER);
}
