import request from "supertest";
import { createApp } from "../src/app.js";
import { loadConfig, type Config } from "../src/config.js";
import { argon2Hasher } from "../src/security/passwords.js";
import { createMemoryRepositories } from "../src/storage/memory.js";

export const PASSWORD = "correct-horse-42-battery";

/**
 * A fresh app with its own in-memory store and a controllable clock.
 * argon2 runs with tiny parameters so the suite stays fast; production
 * parameters are covered separately in passwords.test.ts.
 */
export function makeTestApp(overrides: Partial<Config> = {}) {
  const clock = { now: Date.UTC(2026, 0, 1) };
  const config: Config = {
    ...loadConfig({ JWT_SECRET: "test-secret-that-is-at-least-32-characters-long" }),
    ...overrides,
  };
  const repos = createMemoryRepositories();
  const app = createApp({
    config,
    repos,
    hasher: argon2Hasher({ memoryCost: 1024, timeCost: 1, parallelism: 1 }),
    now: () => clock.now,
  });
  const http = request(app);

  return {
    app,
    http,
    repos,
    config,
    clock,
    advance(seconds: number) {
      clock.now += seconds * 1000;
    },
    register(email = "alice@example.com", password = PASSWORD) {
      return http.post("/auth/register").send({ email, password });
    },
    login(email = "alice@example.com", password = PASSWORD, totpCode?: string) {
      return http.post("/auth/login").send({ email, password, ...(totpCode && { totpCode }) });
    },
    refresh(refreshToken: string) {
      return http.post("/auth/refresh").send({ refreshToken });
    },
    me(accessToken: string) {
      return http.get("/me").set("Authorization", `Bearer ${accessToken}`);
    },
  };
}
