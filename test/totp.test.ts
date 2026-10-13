import { describe, expect, it } from "vitest";
import {
  base32Decode,
  base32Encode,
  generateTotpSecret,
  hotp,
  otpauthUri,
  totp,
  verifyTotp,
  type TotpAlgorithm,
} from "../src/security/totp.js";

// RFC 6238 Appendix B. Each algorithm uses a seed of the matching length.
const SEEDS: Record<TotpAlgorithm, Buffer> = {
  sha1: Buffer.from("12345678901234567890", "ascii"),
  sha256: Buffer.from("12345678901234567890123456789012", "ascii"),
  sha512: Buffer.from("1234567890123456789012345678901234567890123456789012345678901234", "ascii"),
};

const RFC6238_VECTORS: Array<[number, TotpAlgorithm, string]> = [
  [59, "sha1", "94287082"],
  [59, "sha256", "46119246"],
  [59, "sha512", "90693936"],
  [1111111109, "sha1", "07081804"],
  [1111111109, "sha256", "68084774"],
  [1111111109, "sha512", "25091201"],
  [1111111111, "sha1", "14050471"],
  [1111111111, "sha256", "67062674"],
  [1111111111, "sha512", "99943326"],
  [1234567890, "sha1", "89005924"],
  [1234567890, "sha256", "91819424"],
  [1234567890, "sha512", "93441116"],
  [2000000000, "sha1", "69279037"],
  [2000000000, "sha256", "90698825"],
  [2000000000, "sha512", "38618901"],
  [20000000000, "sha1", "65353130"],
  [20000000000, "sha256", "77737706"],
  [20000000000, "sha512", "47863826"],
];

describe("TOTP (RFC 6238)", () => {
  it.each(RFC6238_VECTORS)("t=%i %s -> %s", (seconds, algorithm, expected) => {
    expect(totp(SEEDS[algorithm], seconds * 1000, { digits: 8, algorithm })).toBe(expected);
  });

  it("matches the RFC 4226 HOTP test vectors (counter 0-9)", () => {
    const expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
    expected.forEach((code, counter) => expect(hotp(SEEDS.sha1, counter)).toBe(code));
  });

  it("accepts codes within +/-1 step of drift and rejects further ones", () => {
    const key = SEEDS.sha1;
    const t = 1_700_000_000_000;
    const step = Math.floor(t / 30_000);
    expect(verifyTotp(key, totp(key, t), t)).toBe(step);
    expect(verifyTotp(key, totp(key, t - 30_000), t)).toBe(step - 1);
    expect(verifyTotp(key, totp(key, t + 30_000), t)).toBe(step + 1);
    expect(verifyTotp(key, totp(key, t - 90_000), t)).toBeNull();
  });

  it("rejects malformed codes without throwing", () => {
    const t = 1_700_000_000_000;
    for (const bad of ["", "12345", "1234567", "abcdef", "12 456"]) {
      expect(verifyTotp(SEEDS.sha1, bad, t)).toBeNull();
    }
  });
});

describe("base32 + enrollment helpers", () => {
  it("encodes the RFC 4648 test vector", () => {
    expect(base32Encode(Buffer.from("foobar"))).toBe("MZXW6YTBOI");
    expect(base32Decode("MZXW6YTBOI======").toString()).toBe("foobar");
  });

  it("round-trips random buffers of every length (property)", () => {
    for (let len = 0; len < 64; len++) {
      const buf = Buffer.from(Array.from({ length: len }, () => Math.floor(Math.random() * 256)));
      expect(base32Decode(base32Encode(buf)).equals(buf)).toBe(true);
    }
  });

  it("generates a 160-bit base32 secret and a scannable otpauth URI", () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(base32Decode(secret)).toHaveLength(20);

    const uri = new URL(otpauthUri({ secret, accountName: "alice@example.com", issuer: "FintechDemo" }));
    expect(uri.protocol).toBe("otpauth:");
    expect(uri.host).toBe("totp");
    expect(decodeURIComponent(uri.pathname)).toBe("/FintechDemo:alice@example.com");
    expect(uri.searchParams.get("secret")).toBe(secret);
    expect(uri.searchParams.get("issuer")).toBe("FintechDemo");
  });
});
