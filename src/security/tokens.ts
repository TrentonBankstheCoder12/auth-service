// Access tokens are short-lived signed JWTs (stateless, cheap to verify).
// Refresh tokens are long-lived *opaque* random strings (stateful, stored
// hashed), because they must be revocable and single-use.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";

export interface AccessTokenClaims {
  sub: string; // user id
  sid: string; // session (token family) id, checked on every request
}

export interface JwtSettings {
  secret: string;
  issuer: string;
  audience: string;
  ttlSeconds: number;
}

export function signAccessToken(claims: AccessTokenClaims, s: JwtSettings, nowMs: number): string {
  return jwt.sign(
    { sid: claims.sid, iat: Math.floor(nowMs / 1000) },
    s.secret,
    {
      algorithm: "HS256",
      subject: claims.sub,
      issuer: s.issuer,
      audience: s.audience,
      expiresIn: s.ttlSeconds,
      jwtid: randomUUID(),
    },
  );
}

/** Throws if the token is invalid, expired, or signed with any other algorithm. */
export function verifyAccessToken(token: string, s: JwtSettings, nowMs: number): AccessTokenClaims {
  const payload = jwt.verify(token, s.secret, {
    // Pinning the algorithm blocks the classic "alg: none" / alg-confusion attacks.
    algorithms: ["HS256"],
    issuer: s.issuer,
    audience: s.audience,
    clockTimestamp: Math.floor(nowMs / 1000),
  });
  if (typeof payload === "string" || typeof payload.sub !== "string" || typeof payload.sid !== "string") {
    throw new Error("Malformed token payload");
  }
  return { sub: payload.sub, sid: payload.sid };
}

/** 256 bits of randomness: unguessable, so a fast hash is enough to store it. */
export function generateRefreshToken(): string {
  return randomBytes(32).toString("base64url");
}

// SHA-256 rather than argon2: argon2 protects *low-entropy* secrets
// (passwords). A 256-bit random token can't be brute forced, and a fast
// deterministic hash lets us look the token up by its hash.
export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}
