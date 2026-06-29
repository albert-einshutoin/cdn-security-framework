"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyValidationError = void 0;
exports.errorMessage = errorMessage;
exports.isErrnoException = isErrnoException;
exports.isPolicyValidationError = isPolicyValidationError;
/** Safely extract a message from an unknown thrown value. */
function errorMessage(e) {
    return e instanceof Error ? e.message : String(e);
}
/** Node ErrnoException guard (e.code === 'ENOENT', etc.). */
function isErrnoException(e) {
    return e instanceof Error && typeof e.code === 'string';
}
/** Thrown by validateAuthGates / validateOriginAuth when validationErrors are available. */
class PolicyValidationError extends Error {
    validationErrors;
    constructor(message, validationErrors) {
        super(message);
        this.validationErrors = validationErrors;
        this.name = 'PolicyValidationError';
    }
}
exports.PolicyValidationError = PolicyValidationError;
function isPolicyValidationError(e) {
    return e instanceof PolicyValidationError;
}
