/** Safely extract a message from an unknown thrown value. */
export declare function errorMessage(e: unknown): string;
/** Node ErrnoException guard (e.code === 'ENOENT', etc.). */
export declare function isErrnoException(e: unknown): e is NodeJS.ErrnoException;
/** Thrown by validateAuthGates / validateOriginAuth when validationErrors are available. */
export declare class PolicyValidationError extends Error {
    readonly validationErrors: string[];
    constructor(message: string, validationErrors: string[]);
}
export declare function isPolicyValidationError(e: unknown): e is PolicyValidationError;
