import type { ErrorRequestHandler, NextFunction, Request, RequestHandler, Response } from "express";
import type { z } from "zod";
import { AppError } from "../errors.js";
import type { FixedWindowRateLimiter } from "../security/rateLimiter.js";
import type { AuthService } from "../service.js";
import type { AccessTokenClaims } from "../security/tokens.js";

/** Express 5 forwards rejected promises to the error handler; this just types the handler. */
type AsyncHandler = (req: Request, res: Response, next: NextFunction) => Promise<void>;
export const handle = (fn: AsyncHandler): RequestHandler => fn;

export function parseBody<S extends z.ZodType>(schema: S, body: unknown): z.infer<S> {
  const result = schema.safeParse(body ?? {});
  if (!result.success) {
    const details = result.error.issues.map((i) => ({ path: i.path.join("."), message: i.message }));
    throw new AppError(400, "VALIDATION_ERROR", "Request body is invalid", details);
  }
  return result.data;
}

// res.locals is untyped; this helper keeps the cast in one place.
export function getClaims(res: Response): AccessTokenClaims {
  return res.locals.auth as AccessTokenClaims;
}

export function requireAuth(auth: AuthService): RequestHandler {
  return async (req, res, next) => {
    const header = req.get("authorization") ?? "";
    const [scheme, token] = header.split(" ");
    if (scheme !== "Bearer" || !token) {
      throw new AppError(401, "UNAUTHORIZED", "Missing or invalid access token", undefined, {
        "WWW-Authenticate": "Bearer",
      });
    }
    res.locals.auth = await auth.authenticate(token);
    next();
  };
}

export function rateLimit(limiter: FixedWindowRateLimiter): RequestHandler {
  return (req, _res, next) => {
    const { allowed, retryAfterSeconds } = limiter.hit(req.ip ?? "unknown");
    if (!allowed) {
      throw new AppError(429, "RATE_LIMITED", "Too many attempts; slow down", undefined, {
        "Retry-After": String(retryAfterSeconds),
      });
    }
    next();
  };
}

export const notFound: RequestHandler = (req) => {
  throw new AppError(404, "NOT_FOUND", `No route for ${req.method} ${req.path}`);
};

/** Every error leaves the service in the same shape: { error: { code, message, details? } }. */
export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  if (err instanceof AppError) {
    if (err.headers) res.set(err.headers);
    res.status(err.status).json({
      error: { code: err.code, message: err.message, ...(err.details !== undefined && { details: err.details }) },
    });
    return;
  }
  // express.json() raises a SyntaxError with status 400 for malformed bodies.
  if (err?.type === "entity.parse.failed") {
    res.status(400).json({ error: { code: "INVALID_JSON", message: "Request body is not valid JSON" } });
    return;
  }
  // Unknown errors: log server-side, never echo internals to the client.
  console.error(err);
  res.status(500).json({ error: { code: "INTERNAL_ERROR", message: "Internal server error" } });
};
