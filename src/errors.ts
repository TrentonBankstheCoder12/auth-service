// One error type for the whole service. The HTTP layer turns it into the
// standard `{ error: { code, message, details? } }` body, so clients can
// branch on a stable machine-readable `code` instead of parsing messages.

export type ErrorCode =
  | "VALIDATION_ERROR"
  | "INVALID_JSON"
  | "EMAIL_TAKEN"
  | "WEAK_PASSWORD"
  | "INVALID_CREDENTIALS"
  | "ACCOUNT_LOCKED"
  | "TOTP_REQUIRED"
  | "INVALID_TOTP"
  | "TOTP_ALREADY_ENABLED"
  | "TOTP_NOT_ENROLLED"
  | "UNAUTHORIZED"
  | "INVALID_REFRESH_TOKEN"
  | "REFRESH_TOKEN_REUSED"
  | "RATE_LIMITED"
  | "NOT_FOUND"
  | "INTERNAL_ERROR";

export class AppError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    message: string,
    readonly details?: unknown,
    /** Extra response headers, e.g. Retry-After. */
    readonly headers?: Record<string, string>,
  ) {
    super(message);
    this.name = "AppError";
  }
}
