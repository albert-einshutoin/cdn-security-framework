"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SENSITIVE_KEY_PATTERN = void 0;
exports.redactSensitiveText = redactSensitiveText;
exports.SENSITIVE_KEY_PATTERN = /(?:authorization|cookie|set[-_]?cookie|api[-_]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|token|secret|password)/i;
function redactSensitiveText(value) {
    return value
        .replace(/([?&][^=\s&#]+)=([^&#\s]*)/g, '$1=[REDACTED]')
        .replace(/(["'](?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|token|password|secret)["']\s*:\s*)(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^,}\r\n]*)/gi, '$1"[REDACTED]"')
        .replace(/\b(authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[-_]?secret|token|password|secret)\s*[:=]\s*[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*/gi, '$1=[REDACTED]')
        .replace(/\b(Digest|AWS4-HMAC-SHA256|Hawk|Signature)\s+(?=[A-Za-z][A-Za-z0-9_-]*\s*=)[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*/gi, '$1 [REDACTED]')
        .replace(/\b(Basic|Bearer|Negotiate)\s+[^\s,;]+(?:\r?\n[ \t]+[^\r\n]*)*/gi, '$1 [REDACTED]');
}
