# Walkthrough: Auth Service

A guide to how this project works and why it was built this way. Read it top to bottom, then try to explain each section out loud without looking. That is roughly what an interviewer will ask you to do.

## 1. Request flow and layers

```
route (app.ts) -> zod parse (schemas.ts) -> AuthService (service.ts) -> repositories (storage/)
                                        \-> security helpers (security/)
```

- **HTTP layer** (`src/app.ts`, `src/http/`) only parses input, calls the service and formats output. It knows about Express; nothing else does.
- **Service** (`src/service.ts`) holds every business rule and throws `AppError` (`src/errors.ts`) with an HTTP status and a stable `code`.
- **Storage** (`src/storage/repository.ts`) is a set of interfaces. `memory.ts` implements them with `Map`s. The service never knows which one it has.
- **Clock is injected** (`now: () => number`). Tests jump 15 minutes forward instead of sleeping, which is why lockout and expiry tests run in milliseconds.

`createApp()` takes all dependencies as arguments and never reads `process.env` itself, so each test gets an isolated app. Only `src/server.ts` reads the environment and listens on a port.

## 2. Password storage: argon2id and policy

A fast hash (SHA-256) lets an attacker with a stolen database test billions of guesses per second on a GPU. **argon2id** is deliberately slow and *memory-hard* (each guess needs ~19 MiB of RAM), which kills GPU parallelism. It also generates a random salt per password, so two users with the same password get different hashes, and precomputed rainbow tables are useless. The salt and parameters are stored inside the hash string (`$argon2id$v=19$m=19456,p=1,t=2$<salt>$<hash>`), so verifying needs nothing else.

The **password policy** follows NIST SP 800-63B: length matters most (12+), check a blocklist of common passwords, and don't force "one symbol, one uppercase" rules that push people to `Password1!`. We also reject passwords containing the email name. The policy returns readable reasons, which the API returns in `details`.

Code: `src/security/passwords.ts`. Tests use tiny argon2 parameters for speed; one test runs the production parameters.

**Timing side channel:** when the email doesn't exist, `login` still runs an argon2 verify against a dummy hash. Without that, "unknown email" would answer in 1 ms and "wrong password" in ~50 ms, and an attacker could enumerate customer emails. Both cases also return the identical `INVALID_CREDENTIALS` body.

## 3. Access tokens vs refresh tokens

| | Access token | Refresh token |
|---|---|---|
| Format | Signed JWT (HS256) | 32 random bytes, base64url |
| Lifetime | 15 minutes | 7 days |
| Stored server-side? | No (stateless) | Yes, as a SHA-256 hash |
| Sent | On every API call | Only to `/auth/refresh` |

The split is a trade-off. Verifying a JWT is just an HMAC check, so it's cheap for every request. But a JWT can't be "un-issued", so it's kept short. The refresh token is long-lived, so it must be revocable, which means it lives in the database.

**Why hash refresh tokens with SHA-256 instead of argon2?** argon2 exists to protect *low-entropy* secrets like passwords. A 256-bit random token can't be brute forced no matter how fast the hash is, and a deterministic fast hash lets us look tokens up by hash. If the database leaks, the attacker gets hashes, not usable tokens.

**JWT hardening:** `verifyAccessToken` pins `algorithms: ["HS256"]` and checks `iss` and `aud`. Pinning the algorithm blocks the classic `alg: none` attack (a test forges one). Code: `src/security/tokens.ts`.

**Session check on every request.** The access token carries a `sid` (session id). `AuthService.authenticate` verifies the signature *and* looks up the session. That costs one read per request, but logout and reuse detection take effect immediately instead of waiting up to 15 minutes for the JWT to expire. In fintech that trade is worth it.

## 4. Refresh rotation and reuse detection

Each login creates a **session**, also called a *token family*. Every refresh token in the family carries that `sessionId`.

```
login        -> R1           (family F)
refresh(R1)  -> R2, R1 marked used
refresh(R2)  -> R3, R2 marked used
refresh(R1)  -> R1 is already used => REUSE => revoke F; R3 is now dead too
```

Why kill the whole family? If R1 shows up a second time, two parties hold it: the real client and a thief. The server can't tell which request is the thief, so it logs both out. The real user just signs in again; the thief loses access. This is the approach recommended in the OAuth 2.0 Security Best Current Practice.

**Race condition:** two requests with the same token arrive at once. Both read `usedAt = null`. `markUsed` is defined as an atomic compare-and-set (in SQL: `UPDATE refresh_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL`, then check the affected row count), so only one wins and the other is treated as reuse. The in-memory version is atomic because there is no `await` between the check and the write. A test fires two concurrent refreshes and asserts one `200` and one `401`.

Code: `AuthService.refresh` in `src/service.ts`; tests in `test/auth.test.ts` under "refresh token rotation".

## 5. TOTP two-factor auth from scratch

**HOTP (RFC 4226)** turns a shared secret and a counter into a short code:

1. `HMAC-SHA1(secret, counter as 8-byte big-endian)` gives 20 bytes.
2. *Dynamic truncation*: the low 4 bits of the last byte pick an offset; read 4 bytes there and drop the top bit (31 bits).
3. `mod 10^6`, left-pad with zeros.

**TOTP (RFC 6238)** is HOTP where `counter = floor(unixSeconds / 30)`. Phone and server compute the same code independently from the clock.

Implementation details worth mentioning:

- **Drift window:** we accept the previous, current and next 30-second step, since phone clocks are rarely exact.
- **Constant-time comparison** (`timingSafeEqual`) so response time doesn't leak how many digits matched.
- **Replay protection:** we store the last accepted time step and reject any code at or before it. Without this, a code shoulder-surfed or phished would work again for up to 90 seconds.
- **Base32:** authenticator apps expect secrets in RFC 4648 base32, so `totp.ts` includes a small encoder/decoder.
- **Two-step enrollment:** `enroll` stores a secret but leaves 2FA off. Only after the user submits a valid code (`verify`) is it enabled. Otherwise a user who never scanned the QR code would lock themselves out.

The test file `test/totp.test.ts` runs all 18 vectors from RFC 6238 Appendix B (SHA-1, SHA-256, SHA-512 at six timestamps), plus the ten RFC 4226 HOTP vectors. Passing those is strong evidence the implementation matches every authenticator app.

Code: `src/security/totp.ts`, `enrollTotp` / `confirmTotp` / `checkTotp` in `src/service.ts`.

## 6. Lockout and rate limiting (two different brakes)

- **Account lockout** (per account): 5 consecutive failures lock the account for 15 minutes and return `423 Locked` with `Retry-After`. A successful login resets the counter. A wrong TOTP code also counts, otherwise someone with a stolen password could try all one million codes.
- **Rate limiting** (per IP): a fixed-window counter allows 20 login attempts per minute per IP. This targets *credential stuffing*: one attacker trying leaked passwords against thousands of different accounts, where per-account lockout never triggers.

Lockout has a known downside: anyone who knows your email can lock you out on purpose. Mitigations used in practice: lock only the failing IP+account pair, use progressive delays instead of hard locks, or require a CAPTCHA after N failures. Being able to discuss this trade-off matters more than the specific numbers.

Code: `recordFailure` in `src/service.ts`, `src/security/rateLimiter.ts`, `rateLimit` in `src/http/middleware.ts`.

## 7. Validation and the error contract

zod schemas (`src/http/schemas.ts`) trim and lowercase email (so `Alice@Example.com` is one account), cap field lengths, and use `.strict()` so unknown fields like `"admin": true` are rejected instead of silently ignored. The error handler (`src/http/middleware.ts`) turns every failure into `{ error: { code, message, details? } }`. Unknown errors become a generic `500 INTERNAL_ERROR`; stack traces are logged, never returned.

`toPublicUser` is an explicit allow-list, so adding a sensitive field to `User` can't leak it in a response by accident.

## 8. Known limitation (be ready to discuss this)

All state is **in memory and per process**. Restarting the server logs everyone out, and if you run three instances behind a load balancer, each has its own rate-limit counters and its own idea of which refresh tokens are used, so reuse detection would break. The fix is a shared store: Postgres for users, sessions and refresh tokens (the repository interfaces are designed for it), and Redis for rate-limit counters. Also, `req.ip` is the direct peer; behind a proxy you must configure Express `trust proxy` correctly or every user shares the proxy's IP. Finally, the TOTP secret is stored in plaintext; production systems encrypt it with a key from a KMS, because unlike a password hash, the server needs the raw secret back.

## Likely interview questions

1. **Why not keep sessions only in JWTs?** JWTs can't be revoked before they expire. Short access tokens + stateful refresh tokens + a session check give you cheap verification *and* instant logout (section 3).
2. **What happens if a refresh token is stolen?** The first time both the thief and the real client use it, the second use is detected as reuse and the whole family is revoked (section 4).
3. **Why argon2id over SHA-256 for passwords?** Slow and memory-hard, defeating GPU cracking; salted per password (section 2).
4. **How does TOTP work and how did you verify your implementation?** HMAC over the time-step counter + dynamic truncation; tested against the RFC 6238 vectors (section 5).
5. **Lockout vs rate limiting?** Lockout protects one account from many guesses; IP rate limiting protects many accounts from one attacker. Mention the lockout-as-DoS trade-off (section 6).
6. **How would you scale this to multiple instances?** Shared DB with the atomic `markUsed` update, Redis for rate limits, and asymmetric JWT keys published via JWKS so other services can verify tokens (section 8).
7. **How do you stop user enumeration?** Identical error bodies and equalized timing for unknown email vs wrong password (section 2).

## Try extending it

- Implement `SqliteRepositories` (e.g. with `better-sqlite3`) and run the same test suite against it
- Add ten single-use recovery codes, stored hashed like refresh tokens
- Add `POST /auth/logout-all` that revokes every session for the user
- Add a "password changed" flow that revokes all existing sessions
- Switch to EdDSA-signed JWTs and expose `/.well-known/jwks.json`
