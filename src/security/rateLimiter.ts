// Fixed-window counter keyed by client IP. This is the outer brake against
// credential stuffing (many accounts from one IP); per-account lockout in
// the service is the inner brake (many guesses at one account).

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

export class FixedWindowRateLimiter {
  private windows = new Map<string, { start: number; count: number }>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  hit(key: string): RateLimitResult {
    const t = this.now();
    let w = this.windows.get(key);
    if (!w || t - w.start >= this.windowMs) {
      w = { start: t, count: 0 };
      this.windows.set(key, w);
      this.sweep(t);
    }
    w.count++;
    const retryAfterSeconds = Math.ceil((w.start + this.windowMs - t) / 1000);
    return { allowed: w.count <= this.max, retryAfterSeconds };
  }

  // Drop expired windows so the map can't grow forever under many IPs.
  private sweep(t: number): void {
    if (this.windows.size < 10_000) return;
    for (const [k, w] of this.windows) if (t - w.start >= this.windowMs) this.windows.delete(k);
  }
}
