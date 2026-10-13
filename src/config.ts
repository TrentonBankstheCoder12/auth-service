// Central configuration. Everything security-sensitive is read from the
// environment so the same build can run in dev, CI and production.

export interface Config {
  jwtSecret: string;
  jwtIssuer: string;
  jwtAudience: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  /** Consecutive failed logins before the account is locked. */
  maxFailedLogins: number;
  lockoutSeconds: number;
  /** Per-IP login attempts allowed per window (brute force / credential stuffing brake). */
  loginRateLimit: { max: number; windowSeconds: number };
  totpIssuer: string;
}

// DEV ONLY. This default exists so `npm run dev` works out of the box.
// It is public (it's in the repo), so production refuses to start with it.
export const DEV_JWT_SECRET = "dev-only-insecure-jwt-secret-change-me-0123456789";

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const jwtSecret = env.JWT_SECRET ?? DEV_JWT_SECRET;
  if (env.NODE_ENV === "production" && jwtSecret === DEV_JWT_SECRET) {
    throw new Error("JWT_SECRET must be set in production");
  }
  if (jwtSecret.length < 32) {
    // HS256 keys shorter than the hash output weaken the signature.
    throw new Error("JWT_SECRET must be at least 32 characters");
  }

  return {
    jwtSecret,
    jwtIssuer: env.JWT_ISSUER ?? "auth-service",
    jwtAudience: env.JWT_AUDIENCE ?? "fintech-api",
    accessTokenTtlSeconds: Number(env.ACCESS_TOKEN_TTL_SECONDS ?? 15 * 60),
    refreshTokenTtlSeconds: Number(env.REFRESH_TOKEN_TTL_SECONDS ?? 7 * 24 * 60 * 60),
    maxFailedLogins: Number(env.MAX_FAILED_LOGINS ?? 5),
    lockoutSeconds: Number(env.LOCKOUT_SECONDS ?? 15 * 60),
    loginRateLimit: {
      max: Number(env.LOGIN_RATE_LIMIT_MAX ?? 20),
      windowSeconds: Number(env.LOGIN_RATE_LIMIT_WINDOW_SECONDS ?? 60),
    },
    totpIssuer: env.TOTP_ISSUER ?? "FintechDemo",
  };
}
