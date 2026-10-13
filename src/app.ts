// Builds the Express app from its dependencies. Nothing here touches
// process.env or listens on a port, so tests can create isolated instances.

import express from "express";
import helmet from "helmet";
import { loadConfig, type Config } from "./config.js";
import { errorHandler, getClaims, handle, notFound, parseBody, rateLimit, requireAuth } from "./http/middleware.js";
import { loginSchema, refreshSchema, registerSchema, totpVerifySchema } from "./http/schemas.js";
import { argon2Hasher, type PasswordHasher } from "./security/passwords.js";
import { FixedWindowRateLimiter } from "./security/rateLimiter.js";
import { AuthService } from "./service.js";
import { createMemoryRepositories } from "./storage/memory.js";
import type { Repositories } from "./storage/repository.js";

export interface AppOptions {
  config?: Config;
  repos?: Repositories;
  hasher?: PasswordHasher;
  now?: () => number;
}

export function createApp(opts: AppOptions = {}) {
  const config = opts.config ?? loadConfig();
  const now = opts.now ?? Date.now;
  const auth = new AuthService({
    repos: opts.repos ?? createMemoryRepositories(),
    hasher: opts.hasher ?? argon2Hasher(),
    config,
    now,
  });
  const loginLimiter = new FixedWindowRateLimiter(
    config.loginRateLimit.max,
    config.loginRateLimit.windowSeconds * 1000,
    now,
  );

  const app = express();
  app.disable("x-powered-by");
  app.use(helmet());
  app.use(express.json({ limit: "10kb" }));
  // Tokens must never be cached by browsers or proxies.
  app.use((_req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  });

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.post(
    "/auth/register",
    handle(async (req, res) => {
      const { email, password } = parseBody(registerSchema, req.body);
      res.status(201).json({ user: await auth.register(email, password) });
    }),
  );

  app.post(
    "/auth/login",
    rateLimit(loginLimiter),
    handle(async (req, res) => {
      const { email, password, totpCode } = parseBody(loginSchema, req.body);
      res.json(await auth.login(email, password, totpCode));
    }),
  );

  app.post(
    "/auth/refresh",
    handle(async (req, res) => {
      const { refreshToken } = parseBody(refreshSchema, req.body);
      res.json(await auth.refresh(refreshToken));
    }),
  );

  const authed = requireAuth(auth);

  app.post(
    "/auth/logout",
    authed,
    handle(async (_req, res) => {
      await auth.logout(getClaims(res).sid);
      res.status(204).end();
    }),
  );

  app.get(
    "/me",
    authed,
    handle(async (_req, res) => {
      res.json({ user: await auth.me(getClaims(res).sub) });
    }),
  );

  app.post(
    "/auth/totp/enroll",
    authed,
    handle(async (_req, res) => {
      res.json(await auth.enrollTotp(getClaims(res).sub));
    }),
  );

  app.post(
    "/auth/totp/verify",
    authed,
    handle(async (req, res) => {
      const { code } = parseBody(totpVerifySchema, req.body);
      res.json({ user: await auth.confirmTotp(getClaims(res).sub, code) });
    }),
  );

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
