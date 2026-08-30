"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SENSITIVE_KEY_PATTERN = void 0;
exports.hasUnsafeSensitiveText = hasUnsafeSensitiveText;
exports.redactSensitiveText = redactSensitiveText;
exports.SENSITIVE_KEY_PATTERN = /(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|api[-_]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|token|secret|password)/i;
const AUTH_SCHEME_PREFIX = /\b(?:Basic|Bearer|Digest|Negotiate|AWS4-HMAC-SHA256|Hawk|Signature)\s+/gi;
const ASSIGNMENT_PREFIX = /(?<![?&])["']?\b(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x-api-key|api[-_]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|token|password|secret)\b["']?\s*[:=]\s*["']?/gi;
const QUERY_PREFIX = /[?&][^=\s&#]+=/g;
const PROVIDER_TOKEN_PATTERN = /\b(?:sk-(?:proj-)?|ghp_|github_pat_|AKIA|(?:sk|pk)_)[A-Za-z0-9_-]{8,}/i;
const REDACTED_MARKER = '[REDACTED]';
function isJsonContinuation(value) {
    const suffix = value.trimStart();
    if (!suffix.startsWith(',') && !suffix.startsWith('}'))
        return false;
    try {
        JSON.parse(`{"__redacted__":"value"${suffix}`);
        return true;
    }
    catch {
        return false;
    }
}
function isSafeLineContinuation(value) {
    if (!/[\r\n]/u.test(value) || /(?:\r\n|\r|\n)[ \t]/u.test(value))
        return false;
    return value.split(/\r\n|\r|\n/u).every((line) => !hasUnsafeSensitiveText(line));
}
function isCompleteRedactedValue(value, markerEnd, query, allowJsonContinuation = false) {
    let index = markerEnd;
    while (index < value.length && /["'}\]]/u.test(value[index] ?? ''))
        index += 1;
    const separatorStart = index;
    if (allowJsonContinuation && isJsonContinuation(value.slice(separatorStart)))
        return true;
    let separatorConsumed = false;
    while (index < value.length && /[,;#]/u.test(value[index] ?? '')) {
        separatorConsumed = true;
        index += 1;
    }
    if (index >= value.length)
        return true;
    if (separatorConsumed) {
        const suffix = value.slice(index);
        return /^\s*$/u.test(suffix) || isSafeLineContinuation(value.slice(separatorStart));
    }
    if (/\s/u.test(value[index] ?? '')) {
        return /^\s*$/u.test(value.slice(index)) || isSafeLineContinuation(value.slice(separatorStart));
    }
    return query && value[index] === '&' && /^[^=\s&#]+=/.test(value.slice(index + 1));
}
function hasUnsafeSensitiveValue(value, prefix, query) {
    for (const match of value.matchAll(prefix)) {
        const markerStart = (match.index ?? 0) + match[0].length;
        if (!value.startsWith(REDACTED_MARKER, markerStart)
            || !isCompleteRedactedValue(value, markerStart + REDACTED_MARKER.length, query)) {
            return true;
        }
    }
    return false;
}
function hasUnsafeAssignmentValue(value) {
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
function hasUnsafeSensitiveText(value) {
    return hasUnsafeSensitiveValue(value, AUTH_SCHEME_PREFIX, false)
        || hasUnsafeAssignmentValue(value)
        || hasUnsafeSensitiveValue(value, QUERY_PREFIX, true)
        || PROVIDER_TOKEN_PATTERN.test(value);
}
function redactSensitiveText(value) {
    return value
        .replace(/([?&][^=\s&#]+)=([^&#\s]*)/g, '$1=[REDACTED]')
        .replace(/(["'](?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|token|password|secret)["']\s*:\s*)(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^,}\r\n]*)/gi, '$1"[REDACTED]"')
        .replace(/\b(authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|token|password|secret)\s*[:=]\s*[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*/gi, '$1=[REDACTED]')
        .replace(/\b(Basic|Bearer|Digest|Negotiate|AWS4-HMAC-SHA256|Hawk|Signature)\s+[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*/gi, '$1 [REDACTED]')
        .replace(/\b(?:sk-(?:proj-)?|ghp_|github_pat_|AKIA|(?:sk|pk)_)[A-Za-z0-9_-]{8,}/gi, REDACTED_MARKER);
}
