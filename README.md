# Auth Service

[![CI](https://github.com/TrentonBankstheCoder12/auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/TrentonBankstheCoder12/auth-service/actions/workflows/ci.yml)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)
![Node.js](https://img.shields.io/badge/node-22%2B-339933?logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-5-000000?logo=express&logoColor=white)
![Vitest](https://img.shields.io/badge/tested_with-vitest-6E9F18?logo=vitest&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

An **authentication service built to the standard a bank or payments app needs**. Passwords are hashed with argon2id, sessions use short-lived JWT access tokens plus single-use rotating refresh tokens, and a stolen refresh token is caught the moment it is replayed: the whole session is revoked. Two-factor auth is TOTP (the 6-digit codes from Google Authenticator or 1Password), implemented from RFC 6238 with nothing but `node:crypto` and checked against the RFC's official test vectors. Account lockout and per-IP rate limiting slow down credential stuffing, the most common attack on fintech logins.

## Features

- **argon2id password hashing** with OWASP parameters and a NIST-style password policy (length first, blocklist, no email in password)
- **Short-lived access tokens:** HS256 JWTs (15 min), algorithm pinned so `alg: none` tricks fail
- **Rotating refresh tokens:** opaque, random, single-use, stored only as SHA-256 hashes
- **Reuse detection:** replaying an already-rotated refresh token revokes the entire token family
- **TOTP two-factor auth (RFC 6238):** enroll (secret + `otpauth://` URI), confirm, then required on every login; replayed codes are rejected
- **Lockout + rate limiting:** 5 consecutive failures lock the account for 15 min (`423` + `Retry-After`); per-IP fixed-window limiter on `/auth/login` (`429`)
- **Instant revocation:** every request checks the session is live, so logout and reuse detection take effect immediately
- **Defensive HTTP:** zod validation with strict schemas, helmet headers, `Cache-Control: no-store`, 10 KB body limit, one consistent error format
- **Pluggable storage:** a repository interface with an in-memory implementation; a SQL version is one new class

## Architecture

```
               ┌───────────────────────────────┐
  HTTP ──────▶ │ src/app.ts                    │  routes, helmet, JSON body limit
               │ src/http/middleware.ts        │  requireAuth, rateLimit, error format
               │ src/http/schemas.ts           │  zod request schemas
               └──────────────┬────────────────┘
                              ▼
               ┌───────────────────────────────┐
               │ src/service.ts (AuthService)  │  register, login, lockout, refresh
               │                               │  rotation + reuse detection, TOTP
               └──┬──────────────┬─────────────┘
                  ▼              ▼
   ┌──────────────────────┐  ┌───────────────────────────────┐
   │ src/security/        │  │ src/storage/repository.ts     │  interfaces
   │  passwords.ts argon2 │  │ src/storage/memory.ts         │  in-memory impl
   │  tokens.ts    JWT    │  │   users ─< sessions ─< refresh│
   │  totp.ts  RFC 6238   │  │                     tokens    │
   │  rateLimiter.ts      │  └───────────────────────────────┘
   └──────────────────────┘
```

## Quick start

```bash
npm ci
npm run dev          # http://localhost:3000, uses the DEV JWT secret (warns on startup)

# Production-style
npm run build
JWT_SECRET="$(openssl rand -base64 48)" NODE_ENV=production npm start
```

The service refuses to start in production without `JWT_SECRET`. Other settings (`ACCESS_TOKEN_TTL_SECONDS`, `MAX_FAILED_LOGINS`, `LOCKOUT_SECONDS`, `LOGIN_RATE_LIMIT_MAX`, ...) are in `src/config.ts`.

## Example

```bash
# Register
curl -X POST localhost:3000/auth/register -H 'Content-Type: application/json' \
  -d '{"email": "alice@example.com", "password": "violet-tractor-17-sunrise"}'

# Log in -> {"accessToken": "...", "refreshToken": "...", "tokenType": "Bearer", "expiresIn": 900}
curl -X POST localhost:3000/auth/login -H 'Content-Type: application/json' \
  -d '{"email": "alice@example.com", "password": "violet-tractor-17-sunrise"}'

curl localhost:3000/me -H "Authorization: Bearer $ACCESS"

# Rotate: the old refresh token is now spent. Using it again revokes the session.
curl -X POST localhost:3000/auth/refresh -H 'Content-Type: application/json' \
  -d "{\"refreshToken\": \"$REFRESH\"}"

# Turn on 2FA: scan otpauthUri as a QR code, then confirm with a code from the app
curl -X POST localhost:3000/auth/totp/enroll -H "Authorization: Bearer $ACCESS"
curl -X POST localhost:3000/auth/totp/verify -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"code": "123456"}'

# From now on login needs {"email", "password", "totpCode"}
```

Every error has the same shape:

```json
{ "error": { "code": "ACCOUNT_LOCKED", "message": "Account temporarily locked after repeated failed logins" } }
```

## API

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/register` | - | Create an account (`201`), `409` if the email exists, `400 WEAK_PASSWORD` with reasons |
| `POST` | `/auth/login` | - | Password (+ `totpCode` if 2FA is on) -> token pair. Rate limited per IP |
| `POST` | `/auth/refresh` | - | Rotate a refresh token -> new pair. Reuse -> `401 REFRESH_TOKEN_REUSED` |
| `POST` | `/auth/logout` | Bearer | Revoke the current session (`204`) |
| `GET` | `/me` | Bearer | Current user profile |
| `POST` | `/auth/totp/enroll` | Bearer | Generate a TOTP secret and `otpauth://` URI |
| `POST` | `/auth/totp/verify` | Bearer | Confirm a code and enable 2FA |
| `GET` | `/health` | - | Liveness check |

## Testing

```bash
npm test         # vitest + supertest
npm run lint     # tsc --noEmit over src and test
```

52 tests cover: all 18 RFC 6238 TOTP vectors (SHA-1/256/512) and the RFC 4226 HOTP vectors; registration, policy and duplicate emails; the error format; login, `/me`, logout; tampered, `alg: none` and expired JWTs; refresh rotation, **reuse detection revoking the whole family**, isolation between sessions, concurrent refresh races; TOTP enrollment, login and replay rejection; lockout, counter reset, TOTP failures counting toward lockout, and per-IP rate limiting. A property-style test checks the invariant that a token family always has exactly one live refresh token. Tests use an injected clock, so lockout and expiry are tested without sleeping.

## What I'd add next

- A Postgres/SQLite repository (the `markUsed` contract maps to a single conditional `UPDATE`)
- Recovery codes for users who lose their authenticator, and encrypting the TOTP secret at rest
- Redis-backed rate limiting so limits hold across multiple instances
- Asymmetric signing (RS256/EdDSA) with a JWKS endpoint so other services verify tokens without the secret
- Audit log of security events (lockouts, reuse detection) for fraud monitoring

See [WALKTHROUGH.md](WALKTHROUGH.md) for the design decisions behind this project.

## License

MIT
