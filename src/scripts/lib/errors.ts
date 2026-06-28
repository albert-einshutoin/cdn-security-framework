/** Safely extract a message from an unknown thrown value. */
export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Node ErrnoException guard (e.code === 'ENOENT', etc.). */
export function isErrnoException(e: unknown): e is NodeJS.ErrnoException {
  return e instanceof Error && typeof (e as NodeJS.ErrnoException).code === 'string';
}

/** Thrown by validateAuthGates / validateOriginAuth when validationErrors are available. */
export class PolicyValidationError extends Error {
  constructor(message: string, public readonly validationErrors: string[]) {
    super(message);
    this.name = 'PolicyValidationError';
  }
}

export function isPolicyValidationError(e: unknown): e is PolicyValidationError {
  return e instanceof PolicyValidationError;
}
