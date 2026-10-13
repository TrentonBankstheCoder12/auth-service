import { describe, expect, it } from "vitest";
import { DEV_JWT_SECRET, loadConfig } from "../src/config.js";
import { argon2Hasher, checkPasswordPolicy, PRODUCTION_ARGON2 } from "../src/security/passwords.js";
import { FixedWindowRateLimiter } from "../src/security/rateLimiter.js";

describe("config", () => {
  it("falls back to the clearly-marked dev secret outside production", () => {
    expect(loadConfig({}).jwtSecret).toBe(DEV_JWT_SECRET);
  });

  it("refuses to start in production with the dev secret or a short secret", () => {
    expect(() => loadConfig({ NODE_ENV: "production" })).toThrow(/JWT_SECRET must be set/);
    expect(() => loadConfig({ JWT_SECRET: "too-short" })).toThrow(/at least 32/);
  });
});

describe("password hashing", () => {
  it("argon2id with production parameters: salted, verifiable, rejects wrong passwords", async () => {
    const hasher = argon2Hasher(PRODUCTION_ARGON2);
    const a = await hasher.hash("correct-horse-42-battery");
    const b = await hasher.hash("correct-horse-42-battery");
    expect(a).toMatch(/^\$argon2id\$v=19\$m=19456,p=1,t=2\$/);
    expect(a).not.toBe(b); // unique salt per hash
    expect(await hasher.verify(a, "correct-horse-42-battery")).toBe(true);
    expect(await hasher.verify(a, "correct-horse-42-batterY")).toBe(false);
    expect(await hasher.verify("not-a-hash", "anything")).toBe(false);
  });

  it("accepts a strong passphrase", () => {
    expect(checkPasswordPolicy("violet-tractor-17-sunrise", "dana@example.com")).toEqual([]);
  });
});

describe("fixed-window rate limiter", () => {
  it("allows max hits per window per key, then resets", () => {
    let now = 0;
    const rl = new FixedWindowRateLimiter(2, 1000, () => now);
    expect(rl.hit("a").allowed).toBe(true);
    expect(rl.hit("a").allowed).toBe(true);
    expect(rl.hit("a").allowed).toBe(false);
    expect(rl.hit("b").allowed).toBe(true); // keys are independent
    now = 1000;
    expect(rl.hit("a").allowed).toBe(true);
  });
});
