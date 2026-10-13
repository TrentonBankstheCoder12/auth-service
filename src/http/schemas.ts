// Request body schemas. Validation happens at the edge so the service can
// trust its inputs (types, lengths, normalized email).

import { z } from "zod";
import { PASSWORD_MAX_LENGTH } from "../security/passwords.js";

// Normalizing here means "Alice@Example.com" and "alice@example.com" are
// the same account everywhere downstream.
const email = z.string().trim().toLowerCase().pipe(z.email().max(254));

// Only bound the length here; the real policy (with readable reasons) lives
// in passwords.ts and runs on register only, so login never leaks policy.
const password = z.string().min(1).max(PASSWORD_MAX_LENGTH);

const totpCode = z.string().regex(/^\d{6}$/, "must be 6 digits");

export const registerSchema = z.object({ email, password }).strict();

export const loginSchema = z.object({ email, password, totpCode: totpCode.optional() }).strict();

export const refreshSchema = z.object({ refreshToken: z.string().min(1).max(512) }).strict();

export const totpVerifySchema = z.object({ code: totpCode }).strict();
