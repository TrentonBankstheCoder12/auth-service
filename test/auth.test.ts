import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it } from "vitest";
import { base32Decode, totp } from "../src/security/totp.js";
import { hashRefreshToken } from "../src/security/tokens.js";
import { makeTestApp, PASSWORD } from "./helpers.js";

type TestApp = ReturnType<typeof makeTestApp>;

async function loggedIn(t: TestApp) {
  await t.register();
  const res = await t.login();
  expect(res.status).toBe(200);
  return res.body as { accessToken: string; refreshToken: string };
}

describe("registration", () => {
  it("creates a user and never returns secrets", async () => {
    const t = makeTestApp();
    const res = await t.register("  Alice@Example.COM ");
    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({ email: "alice@example.com", totpEnabled: false });
    expect(Object.keys(res.body.user).sort()).toEqual(["createdAt", "email", "id", "totpEnabled"]);

    const stored = await t.repos.users.findByEmail("alice@example.com");
    expect(stored?.passwordHash).toMatch(/^\$argon2id\$/);
    expect(stored?.passwordHash).not.toContain(PASSWORD);
  });

  it("rejects duplicate emails case-insensitively", async () => {
    const t = makeTestApp();
    await t.register("bob@example.com");
    const res = await t.register("BOB@example.com");
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe("EMAIL_TAKEN");
  });

  it("enforces the password policy with readable reasons", async () => {
    const t = makeTestApp();
    const cases: Array<[string, string]> = [
      ["short1", "at least 12"],
      ["onlyletterslong", "letter and one digit"],
      ["Password1234", "too common"],
      ["carol-is-great-99", "email name"],
    ];
    for (const [password, reason] of cases) {
      const res = await t.register("carol@example.com", password);
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("WEAK_PASSWORD");
      expect(res.body.error.details.join(" ")).toContain(reason);
    }
  });

  it("returns a consistent error shape for invalid input and bad JSON", async () => {
    const t = makeTestApp();
    const invalid = await t.http.post("/auth/register").send({ email: "not-an-email", password: PASSWORD, admin: true });
    expect(invalid.status).toBe(400);
    expect(invalid.body.error.code).toBe("VALIDATION_ERROR");
    expect(invalid.body.error.details.map((d: { path: string }) => d.path)).toContain("email");

    const badJson = await t.http.post("/auth/register").set("Content-Type", "application/json").send("{oops");
    expect(badJson.status).toBe(400);
    expect(badJson.body).toEqual({ error: { code: "INVALID_JSON", message: expect.any(String) } });

    const missing = await t.http.get("/nope");
    expect(missing.status).toBe(404);
    expect(missing.body.error.code).toBe("NOT_FOUND");
  });
});

describe("login, /me and logout", () => {
  it("issues an access + refresh token pair that unlocks /me", async () => {
    const t = makeTestApp();
    const tokens = await loggedIn(t);
    expect(tokens).toMatchObject({ tokenType: "Bearer", expiresIn: 900 });

    const me = await t.me(tokens.accessToken);
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe("alice@example.com");
  });

  it("uses one generic error for unknown email and wrong password", async () => {
    const t = makeTestApp();
    await t.register();
    const wrongPw = await t.login("alice@example.com", "wrong-password-123");
    const noUser = await t.login("nobody@example.com", PASSWORD);
    expect(wrongPw.status).toBe(401);
    expect(noUser.status).toBe(401);
    expect(wrongPw.body).toEqual(noUser.body);
  });

  it("rejects missing, tampered, wrong-algorithm and expired access tokens", async () => {
    const t = makeTestApp();
    const { accessToken } = await loggedIn(t);

    expect((await t.http.get("/me")).status).toBe(401);
    expect((await t.me(accessToken.slice(0, -2) + "xx")).status).toBe(401);

    // "alg: none" token carrying a valid-looking payload must be refused.
    const payload = jwt.decode(accessToken) as Record<string, unknown>;
    const unsigned = jwt.sign(payload, "", { algorithm: "none" });
    expect((await t.me(unsigned)).status).toBe(401);

    t.advance(15 * 60 + 1);
    const expired = await t.me(accessToken);
    expect(expired.status).toBe(401);
    expect(expired.body.error.code).toBe("UNAUTHORIZED");
  });

  it("logout revokes the session: access and refresh tokens both stop working", async () => {
    const t = makeTestApp();
    const { accessToken, refreshToken } = await loggedIn(t);

    const out = await t.http.post("/auth/logout").set("Authorization", `Bearer ${accessToken}`);
    expect(out.status).toBe(204);

    expect((await t.me(accessToken)).status).toBe(401);
    expect((await t.refresh(refreshToken)).status).toBe(401);
  });

  it("sets security headers via helmet and disables caching", async () => {
    const t = makeTestApp();
    const res = await t.http.get("/health");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["strict-transport-security"]).toBeDefined();
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["x-powered-by"]).toBeUndefined();
  });
});

describe("refresh token rotation", () => {
  let t: TestApp;
  beforeEach(() => {
    t = makeTestApp();
  });

  it("rotates: each refresh returns a new pair and stores only hashes", async () => {
    const first = await loggedIn(t);
    const res = await t.refresh(first.refreshToken);
    expect(res.status).toBe(200);
    expect(res.body.refreshToken).not.toBe(first.refreshToken);
    expect((await t.me(res.body.accessToken)).status).toBe(200);

    // Stored by hash; the raw value is not a key in the store.
    expect(await t.repos.refreshTokens.findByHash(hashRefreshToken(res.body.refreshToken))).not.toBeNull();
    expect(await t.repos.refreshTokens.findByHash(res.body.refreshToken)).toBeNull();
  });

  it("detects reuse of a rotated token and revokes the whole family", async () => {
    const first = await loggedIn(t);
    const second = (await t.refresh(first.refreshToken)).body;
    const third = (await t.refresh(second.refreshToken)).body;

    // Attacker (or a confused client) replays the very first token.
    const replay = await t.refresh(first.refreshToken);
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe("REFRESH_TOKEN_REUSED");

    // Every token in the family is now dead, including the newest one.
    expect((await t.refresh(third.refreshToken)).status).toBe(401);
    expect((await t.me(third.accessToken)).status).toBe(401);
  });

  it("reuse in one session does not affect the user's other sessions", async () => {
    const laptop = await loggedIn(t);
    const phone = (await t.login()).body;
    await t.refresh(laptop.refreshToken);
    await t.refresh(laptop.refreshToken); // reuse -> laptop family revoked

    expect((await t.me(phone.accessToken)).status).toBe(200);
    expect((await t.refresh(phone.refreshToken)).status).toBe(200);
  });

  it("only one of two concurrent refreshes with the same token can win", async () => {
    const { refreshToken } = await loggedIn(t);
    const results = await Promise.all([t.refresh(refreshToken), t.refresh(refreshToken)]);
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 401]);
  });

  it("rejects expired and unknown refresh tokens", async () => {
    const { refreshToken } = await loggedIn(t);
    expect((await t.refresh("not-a-real-token")).body.error.code).toBe("INVALID_REFRESH_TOKEN");
    t.advance(7 * 24 * 60 * 60 + 1);
    const res = await t.refresh(refreshToken);
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("INVALID_REFRESH_TOKEN");
  });

  it("invariant: across a random sequence of refreshes, exactly one token per family is live", async () => {
    const { refreshToken } = await loggedIn(t);
    const issued = [refreshToken];
    let current = refreshToken;
    for (let i = 0; i < 15; i++) {
      const res = await t.refresh(current);
      expect(res.status).toBe(200);
      current = res.body.refreshToken;
      issued.push(current);
    }
    const records = await Promise.all(issued.map((tok) => t.repos.refreshTokens.findByHash(hashRefreshToken(tok))));
    const unused = records.filter((r) => r?.usedAt === null);
    expect(unused).toHaveLength(1);
    expect(new Set(records.map((r) => r?.sessionId)).size).toBe(1);
  });
});

describe("TOTP two-factor auth", () => {
  async function enrollAndEnable(t: TestApp) {
    const { accessToken } = await loggedIn(t);
    const auth = { Authorization: `Bearer ${accessToken}` };

    const enroll = await t.http.post("/auth/totp/enroll").set(auth);
    expect(enroll.status).toBe(200);
    expect(enroll.body.otpauthUri).toContain(`secret=${enroll.body.secret}`);
    const key = base32Decode(enroll.body.secret);

    const bad = totp(key, t.clock.now) === "000000" ? "111111" : "000000";
    const wrong = await t.http.post("/auth/totp/verify").set(auth).send({ code: bad });
    expect(wrong.status).toBe(400);
    expect(wrong.body.error.code).toBe("INVALID_TOTP");

    const ok = await t.http.post("/auth/totp/verify").set(auth).send({ code: totp(key, t.clock.now) });
    expect(ok.status).toBe(200);
    expect(ok.body.user.totpEnabled).toBe(true);
    return key;
  }

  it("is not active until the user confirms a code", async () => {
    const t = makeTestApp();
    const { accessToken } = await loggedIn(t);
    await t.http.post("/auth/totp/enroll").set("Authorization", `Bearer ${accessToken}`);
    // Enrolled but not confirmed: password alone still works.
    expect((await t.login()).status).toBe(200);
  });

  it("requires a valid code on login once enabled", async () => {
    const t = makeTestApp();
    const key = await enrollAndEnable(t);
    t.advance(30); // next time step, so the enrollment code can't be replayed

    const noCode = await t.login();
    expect(noCode.status).toBe(401);
    expect(noCode.body.error.code).toBe("TOTP_REQUIRED");

    const ok = await t.login("alice@example.com", PASSWORD, totp(key, t.clock.now));
    expect(ok.status).toBe(200);
    expect(ok.body.accessToken).toBeDefined();
  });

  it("rejects replay of an already-used code", async () => {
    const t = makeTestApp();
    const key = await enrollAndEnable(t);
    t.advance(30);
    const code = totp(key, t.clock.now);
    expect((await t.login("alice@example.com", PASSWORD, code)).status).toBe(200);
    const replay = await t.login("alice@example.com", PASSWORD, code);
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe("INVALID_TOTP");
  });

  it("cannot be enrolled twice", async () => {
    const t = makeTestApp();
    await enrollAndEnable(t);
    t.advance(30);
    const key = base32Decode((await t.repos.users.findByEmail("alice@example.com"))!.totpSecret!);
    const { accessToken } = (await t.login("alice@example.com", PASSWORD, totp(key, t.clock.now))).body;
    const again = await t.http.post("/auth/totp/enroll").set("Authorization", `Bearer ${accessToken}`);
    expect(again.status).toBe(409);
    expect(again.body.error.code).toBe("TOTP_ALREADY_ENABLED");
  });
});

describe("lockout and rate limiting", () => {
  it("locks the account after 5 consecutive failures, even for the right password", async () => {
    const t = makeTestApp();
    await t.register();
    for (let i = 0; i < 4; i++) {
      expect((await t.login("alice@example.com", "wrong-password-123")).status).toBe(401);
    }
    const fifth = await t.login("alice@example.com", "wrong-password-123");
    expect(fifth.status).toBe(423);
    expect(fifth.body.error.code).toBe("ACCOUNT_LOCKED");
    expect(Number(fifth.headers["retry-after"])).toBe(15 * 60);

    const correct = await t.login();
    expect(correct.status).toBe(423);

    t.advance(15 * 60);
    expect((await t.login()).status).toBe(200);
  });

  it("a successful login resets the failure counter", async () => {
    const t = makeTestApp();
    await t.register();
    for (let i = 0; i < 4; i++) await t.login("alice@example.com", "wrong-password-123");
    expect((await t.login()).status).toBe(200);
    for (let i = 0; i < 4; i++) {
      expect((await t.login("alice@example.com", "wrong-password-123")).status).toBe(401);
    }
  });

  it("wrong TOTP codes count toward lockout", async () => {
    const t = makeTestApp({ maxFailedLogins: 3 });
    const { accessToken } = await loggedIn(t);
    const auth = { Authorization: `Bearer ${accessToken}` };
    const { secret } = (await t.http.post("/auth/totp/enroll").set(auth)).body;
    const key = base32Decode(secret);
    await t.http.post("/auth/totp/verify").set(auth).send({ code: totp(key, t.clock.now) });
    t.advance(30);

    const bad = totp(key, t.clock.now) === "123456" ? "654321" : "123456";
    expect((await t.login("alice@example.com", PASSWORD, bad)).status).toBe(401);
    expect((await t.login("alice@example.com", PASSWORD, bad)).status).toBe(401);
    expect((await t.login("alice@example.com", PASSWORD, bad)).status).toBe(423);
  });

  it("rate limits login attempts per IP across accounts", async () => {
    const t = makeTestApp({ loginRateLimit: { max: 3, windowSeconds: 60 } });
    for (let i = 0; i < 3; i++) {
      expect((await t.login(`user${i}@example.com`, PASSWORD)).status).toBe(401);
    }
    const limited = await t.login("user9@example.com", PASSWORD);
    expect(limited.status).toBe(429);
    expect(limited.body.error.code).toBe("RATE_LIMITED");
    expect(limited.headers["retry-after"]).toBe("60");

    t.advance(60);
    expect((await t.login("user9@example.com", PASSWORD)).status).toBe(401);
  });
});
