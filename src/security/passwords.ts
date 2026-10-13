// Password hashing and password policy.
//
// argon2id is the OWASP-recommended algorithm: it is deliberately slow and
// memory-hard, so an attacker who steals the user table can't cheaply try
// billions of guesses on GPUs. The salt and parameters are embedded in the
// encoded hash string, so verify() needs nothing else.

import argon2 from "argon2";

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(hash: string, password: string): Promise<boolean>;
}

export interface Argon2Params {
  memoryCost: number; // KiB
  timeCost: number; // iterations
  parallelism: number;
}

// OWASP 2023 baseline for argon2id: 19 MiB, 2 iterations, 1 lane.
export const PRODUCTION_ARGON2: Argon2Params = { memoryCost: 19_456, timeCost: 2, parallelism: 1 };

export function argon2Hasher(params: Argon2Params = PRODUCTION_ARGON2): PasswordHasher {
  return {
    hash: (password) => argon2.hash(password, { type: argon2.argon2id, ...params }),
    async verify(hash, password) {
      try {
        return await argon2.verify(hash, password);
      } catch {
        return false; // malformed hash: treat as mismatch, never as success
      }
    },
  };
}

// ---------------------------------------------------------------- policy
// NIST SP 800-63B favours length over composition rules, so the main rule
// is a 12-character minimum plus a blocklist. We still ask for a letter and
// a digit as a cheap guard against "aaaaaaaaaaaa".

export const PASSWORD_MIN_LENGTH = 12;
// argon2 accepts long inputs, but an unbounded field is a cheap DoS vector.
export const PASSWORD_MAX_LENGTH = 128;

const COMMON_PASSWORDS = new Set([
  "password1234",
  "password123!",
  "123456789012",
  "qwertyuiop12",
  "letmein12345",
  "welcome12345",
  "iloveyou1234",
  "admin1234567",
]);

/** Returns a list of human-readable problems; empty means the password is acceptable. */
export function checkPasswordPolicy(password: string, email: string): string[] {
  const problems: string[] = [];
  if (password.length < PASSWORD_MIN_LENGTH) {
    problems.push(`must be at least ${PASSWORD_MIN_LENGTH} characters`);
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    problems.push(`must be at most ${PASSWORD_MAX_LENGTH} characters`);
  }
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    problems.push("must contain at least one letter and one digit");
  }
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    problems.push("is too common");
  }
  const localPart = email.split("@")[0]?.toLowerCase() ?? "";
  if (localPart.length >= 4 && password.toLowerCase().includes(localPart)) {
    problems.push("must not contain your email name");
  }
  return problems;
}
