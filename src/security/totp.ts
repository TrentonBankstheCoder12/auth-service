// TOTP (RFC 6238) built on HOTP (RFC 4226) using only node:crypto.
//
// HOTP: code = Truncate(HMAC(secret, counter)) mod 10^digits
// TOTP: HOTP where counter = floor(unixSeconds / stepSeconds)
//
// The authenticator app and the server share the secret once (via QR code),
// then each derives the same 6 digits from the current time independently.

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export type TotpAlgorithm = "sha1" | "sha256" | "sha512";

export interface TotpOptions {
  stepSeconds?: number;
  digits?: number;
  algorithm?: TotpAlgorithm;
}

const DEFAULTS = { stepSeconds: 30, digits: 6, algorithm: "sha1" as TotpAlgorithm };

// ---------------------------------------------------------------- base32
// Authenticator apps expect the secret in RFC 4648 base32 (A-Z, 2-7):
// it survives being typed by hand, unlike base64.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out; // unpadded, which is what otpauth:// URIs use
}

export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// ---------------------------------------------------------------- HOTP / TOTP

export function hotp(
  key: Buffer,
  counter: number,
  digits = DEFAULTS.digits,
  algorithm: TotpAlgorithm = DEFAULTS.algorithm,
): string {
  // Counter is an 8-byte big-endian integer (RFC 4226 section 5.2).
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac(algorithm, key).update(msg).digest();

  // Dynamic truncation: the low 4 bits of the last byte pick an offset,
  // then take 31 bits from there (top bit masked to avoid sign issues).
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];

  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

export function timeStep(timeMs: number, stepSeconds = DEFAULTS.stepSeconds): number {
  return Math.floor(timeMs / 1000 / stepSeconds);
}

export function totp(key: Buffer, timeMs: number, opts: TotpOptions = {}): string {
  const o = { ...DEFAULTS, ...opts };
  return hotp(key, timeStep(timeMs, o.stepSeconds), o.digits, o.algorithm);
}

/**
 * Check a user-supplied code, allowing +/- `window` steps of clock drift.
 * Returns the matching time step (so the caller can block replays of the
 * same code) or null if nothing matched.
 */
export function verifyTotp(
  key: Buffer,
  code: string,
  timeMs: number,
  opts: TotpOptions & { window?: number } = {},
): number | null {
  const o = { ...DEFAULTS, window: 1, ...opts };
  if (!/^\d+$/.test(code) || code.length !== o.digits) return null;

  const current = timeStep(timeMs, o.stepSeconds);
  for (let delta = -o.window; delta <= o.window; delta++) {
    const step = current + delta;
    if (step < 0) continue;
    const expected = hotp(key, step, o.digits, o.algorithm);
    // Constant-time compare so response timing can't leak matching digits.
    if (timingSafeEqual(Buffer.from(expected), Buffer.from(code))) return step;
  }
  return null;
}

// ---------------------------------------------------------------- enrollment

/** 20 random bytes = 160 bits, the HMAC-SHA1 block-friendly size RFC 4226 recommends. */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

/** The URI encoded into the QR code that authenticator apps scan. */
export function otpauthUri(params: { secret: string; accountName: string; issuer: string }): string {
  const label = encodeURIComponent(`${params.issuer}:${params.accountName}`);
  const query = new URLSearchParams({
    secret: params.secret,
    issuer: params.issuer,
    algorithm: "SHA1",
    digits: String(DEFAULTS.digits),
    period: String(DEFAULTS.stepSeconds),
  });
  return `otpauth://totp/${label}?${query.toString()}`;
}
