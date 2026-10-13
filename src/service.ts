// Business rules for authentication. No Express here: the service takes
// plain values and throws AppError, which keeps it unit-testable and lets
// the HTTP layer stay thin.

import { randomUUID } from "node:crypto";
import type { Config } from "./config.js";
import { AppError } from "./errors.js";
import { checkPasswordPolicy, type PasswordHasher } from "./security/passwords.js";
import {
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
  verifyAccessToken,
  type AccessTokenClaims,
  type JwtSettings,
} from "./security/tokens.js";
import { base32Decode, generateTotpSecret, otpauthUri, verifyTotp } from "./security/totp.js";
import type { Repositories, User } from "./storage/repository.js";

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: "Bearer";
  expiresIn: number; // access token lifetime in seconds
}

export interface PublicUser {
  id: string;
  email: string;
  totpEnabled: boolean;
  createdAt: string;
}

export interface AuthServiceDeps {
  repos: Repositories;
  hasher: PasswordHasher;
  config: Config;
  /** Injected clock so tests can jump past lockouts and token expiry. */
  now?: () => number;
}

export function toPublicUser(u: User): PublicUser {
  // Explicit allow-list: never serialize the hash or TOTP secret by accident.
  return { id: u.id, email: u.email, totpEnabled: u.totpEnabled, createdAt: new Date(u.createdAt).toISOString() };
}

export class AuthService {
  private readonly repos: Repositories;
  private readonly hasher: PasswordHasher;
  private readonly config: Config;
  private readonly now: () => number;
  private readonly jwt: JwtSettings;
  // Used to burn the same CPU time when the email doesn't exist (see login).
  private dummyHash: Promise<string> | null = null;

  constructor(deps: AuthServiceDeps) {
    this.repos = deps.repos;
    this.hasher = deps.hasher;
    this.config = deps.config;
    this.now = deps.now ?? Date.now;
    this.jwt = {
      secret: deps.config.jwtSecret,
      issuer: deps.config.jwtIssuer,
      audience: deps.config.jwtAudience,
      ttlSeconds: deps.config.accessTokenTtlSeconds,
    };
  }

  // ------------------------------------------------------------ register

  async register(email: string, password: string): Promise<PublicUser> {
    const problems = checkPasswordPolicy(password, email);
    if (problems.length > 0) {
      throw new AppError(400, "WEAK_PASSWORD", "Password does not meet policy", problems);
    }
    if (await this.repos.users.findByEmail(email)) {
      throw new AppError(409, "EMAIL_TAKEN", "An account with this email already exists");
    }
    const user: User = {
      id: randomUUID(),
      email,
      passwordHash: await this.hasher.hash(password),
      createdAt: this.now(),
      failedLoginCount: 0,
      lockedUntil: null,
      totpEnabled: false,
      totpSecret: null,
      totpLastUsedStep: null,
    };
    try {
      await this.repos.users.create(user);
    } catch {
      // Lost a race with a concurrent registration for the same email.
      throw new AppError(409, "EMAIL_TAKEN", "An account with this email already exists");
    }
    return toPublicUser(user);
  }

  // ------------------------------------------------------------ login

  async login(email: string, password: string, totpCode?: string): Promise<TokenPair> {
    const user = await this.repos.users.findByEmail(email);
    if (!user) {
      // Verify against a throwaway hash so "no such user" takes as long as
      // "wrong password". Otherwise response time reveals which emails exist.
      this.dummyHash ??= this.hasher.hash("timing-equalizer-not-a-real-password");
      await this.hasher.verify(await this.dummyHash, password);
      throw invalidCredentials();
    }

    const now = this.now();
    if (user.lockedUntil !== null && user.lockedUntil > now) {
      throw lockedError(user.lockedUntil, now);
    }

    if (!(await this.hasher.verify(user.passwordHash, password))) {
      await this.recordFailure(user, now);
      throw invalidCredentials();
    }

    if (user.totpEnabled) {
      if (!totpCode) {
        // Password was right but a second factor is needed. Not counted as
        // a failure; the client should prompt for the code and retry.
        throw new AppError(401, "TOTP_REQUIRED", "Two-factor code required");
      }
      const step = this.checkTotp(user, totpCode, now);
      if (step === null) {
        // A wrong 6-digit code counts toward lockout, otherwise an attacker
        // with the password could try all 10^6 codes.
        await this.recordFailure(user, now);
        throw new AppError(401, "INVALID_TOTP", "Invalid two-factor code");
      }
      await this.repos.users.update(user.id, { totpLastUsedStep: step });
    }

    await this.repos.users.update(user.id, { failedLoginCount: 0, lockedUntil: null });

    const sessionId = randomUUID();
    await this.repos.sessions.create({
      id: sessionId,
      userId: user.id,
      createdAt: now,
      revokedAt: null,
      revokedReason: null,
    });
    return this.issueTokens(user.id, sessionId, now);
  }

  private async recordFailure(user: User, now: number): Promise<void> {
    const failures = user.failedLoginCount + 1;
    if (failures >= this.config.maxFailedLogins) {
      const lockedUntil = now + this.config.lockoutSeconds * 1000;
      await this.repos.users.update(user.id, { failedLoginCount: 0, lockedUntil });
      throw lockedError(lockedUntil, now);
    }
    await this.repos.users.update(user.id, { failedLoginCount: failures });
  }

  /** Returns the accepted time step, or null. Rejects replays of an already-used code. */
  private checkTotp(user: User, code: string, now: number): number | null {
    if (!user.totpSecret) return null;
    const step = verifyTotp(base32Decode(user.totpSecret), code, now);
    if (step === null) return null;
    if (user.totpLastUsedStep !== null && step <= user.totpLastUsedStep) return null;
    return step;
  }

  // ------------------------------------------------------------ refresh

  async refresh(rawRefreshToken: string): Promise<TokenPair> {
    const now = this.now();
    const tokenHash = hashRefreshToken(rawRefreshToken);
    const record = await this.repos.refreshTokens.findByHash(tokenHash);
    if (!record) throw invalidRefresh();

    const session = await this.repos.sessions.findById(record.sessionId);
    if (!session || session.revokedAt !== null) throw invalidRefresh();

    // Reuse detection. A refresh token is single-use; if one that was
    // already rotated shows up again, either the legitimate client or an
    // attacker holds a stolen copy, and we can't tell which. So we kill the
    // whole family: both parties are logged out and the user re-authenticates.
    if (record.usedAt !== null || !(await this.repos.refreshTokens.markUsed(tokenHash, now))) {
      await this.repos.sessions.revoke(session.id, "reuse_detected", now);
      throw new AppError(401, "REFRESH_TOKEN_REUSED", "Refresh token reuse detected; session revoked");
    }

    if (record.expiresAt <= now) throw invalidRefresh();

    return this.issueTokens(record.userId, session.id, now);
  }

  private async issueTokens(userId: string, sessionId: string, now: number): Promise<TokenPair> {
    const refreshToken = generateRefreshToken();
    await this.repos.refreshTokens.create({
      tokenHash: hashRefreshToken(refreshToken),
      sessionId,
      userId,
      expiresAt: now + this.config.refreshTokenTtlSeconds * 1000,
      usedAt: null,
    });
    return {
      accessToken: signAccessToken({ sub: userId, sid: sessionId }, this.jwt, now),
      refreshToken,
      tokenType: "Bearer",
      expiresIn: this.config.accessTokenTtlSeconds,
    };
  }

  // ------------------------------------------------------------ access tokens

  /**
   * Verifies the JWT *and* that its session is still live. The extra lookup
   * costs one read per request but means logout and reuse detection take
   * effect immediately instead of after the access token expires.
   */
  async authenticate(accessToken: string): Promise<AccessTokenClaims> {
    let claims: AccessTokenClaims;
    try {
      claims = verifyAccessToken(accessToken, this.jwt, this.now());
    } catch {
      throw unauthorized();
    }
    const session = await this.repos.sessions.findById(claims.sid);
    if (!session || session.revokedAt !== null || session.userId !== claims.sub) throw unauthorized();
    return claims;
  }

  async logout(sessionId: string): Promise<void> {
    await this.repos.sessions.revoke(sessionId, "logout", this.now());
  }

  async me(userId: string): Promise<PublicUser> {
    const user = await this.repos.users.findById(userId);
    if (!user) throw unauthorized();
    return toPublicUser(user);
  }

  // ------------------------------------------------------------ TOTP enrollment

  /**
   * Step 1: generate a secret and hand it to the user (as a QR code of the
   * otpauth URI). 2FA is NOT on yet: if the user never scanned it they
   * would be locked out, so we wait for proof in step 2.
   */
  async enrollTotp(userId: string): Promise<{ secret: string; otpauthUri: string }> {
    const user = await this.repos.users.findById(userId);
    if (!user) throw unauthorized();
    if (user.totpEnabled) {
      throw new AppError(409, "TOTP_ALREADY_ENABLED", "Two-factor authentication is already enabled");
    }
    const secret = generateTotpSecret();
    await this.repos.users.update(userId, { totpSecret: secret, totpLastUsedStep: null });
    return {
      secret,
      otpauthUri: otpauthUri({ secret, accountName: user.email, issuer: this.config.totpIssuer }),
    };
  }

  /** Step 2: the user submits a code from their app, proving they saved the secret. */
  async confirmTotp(userId: string, code: string): Promise<PublicUser> {
    const user = await this.repos.users.findById(userId);
    if (!user) throw unauthorized();
    if (user.totpEnabled) {
      throw new AppError(409, "TOTP_ALREADY_ENABLED", "Two-factor authentication is already enabled");
    }
    if (!user.totpSecret) {
      throw new AppError(400, "TOTP_NOT_ENROLLED", "Call /auth/totp/enroll first");
    }
    const step = this.checkTotp(user, code, this.now());
    if (step === null) throw new AppError(400, "INVALID_TOTP", "Invalid two-factor code");
    await this.repos.users.update(userId, { totpEnabled: true, totpLastUsedStep: step });
    return toPublicUser({ ...user, totpEnabled: true });
  }
}

// One generic message for unknown email and wrong password: don't reveal
// which emails have accounts.
const invalidCredentials = () => new AppError(401, "INVALID_CREDENTIALS", "Invalid email or password");
const invalidRefresh = () => new AppError(401, "INVALID_REFRESH_TOKEN", "Invalid or expired refresh token");
const unauthorized = () => new AppError(401, "UNAUTHORIZED", "Missing or invalid access token");

function lockedError(lockedUntil: number, now: number): AppError {
  const retryAfter = Math.max(1, Math.ceil((lockedUntil - now) / 1000));
  return new AppError(423, "ACCOUNT_LOCKED", "Account temporarily locked after repeated failed logins", undefined, {
    "Retry-After": String(retryAfter),
  });
}
