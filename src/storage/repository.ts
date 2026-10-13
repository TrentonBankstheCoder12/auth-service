// Storage contracts. The service layer only talks to these interfaces, so
// swapping the in-memory store for Postgres means writing one new class,
// not touching business logic. Methods are async for that reason even
// though the in-memory version could be synchronous.

export interface User {
  id: string;
  email: string; // normalized: trimmed + lowercased
  passwordHash: string;
  createdAt: number;
  failedLoginCount: number;
  lockedUntil: number | null;
  totpEnabled: boolean;
  /** Base32 secret. Pending until the user proves they can generate a code. */
  totpSecret: string | null;
  /** Last accepted TOTP time step, so the same code can't be replayed. */
  totpLastUsedStep: number | null;
}

/**
 * A login session = one "token family". Every refresh token minted by
 * rotating from the original login shares the same session id, which is
 * what lets reuse detection revoke the whole chain at once.
 */
export interface Session {
  id: string;
  userId: string;
  createdAt: number;
  revokedAt: number | null;
  revokedReason: "logout" | "reuse_detected" | null;
}

export interface RefreshTokenRecord {
  /** SHA-256 of the raw token. The raw token is never stored. */
  tokenHash: string;
  sessionId: string;
  userId: string;
  expiresAt: number;
  /** Set when this token is rotated. A second use after this is reuse. */
  usedAt: number | null;
}

export interface UserRepository {
  create(user: User): Promise<void>;
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  update(id: string, patch: Partial<Omit<User, "id">>): Promise<void>;
}

export interface SessionRepository {
  create(session: Session): Promise<void>;
  findById(id: string): Promise<Session | null>;
  revoke(id: string, reason: NonNullable<Session["revokedReason"]>, at: number): Promise<void>;
}

export interface RefreshTokenRepository {
  create(record: RefreshTokenRecord): Promise<void>;
  findByHash(tokenHash: string): Promise<RefreshTokenRecord | null>;
  /**
   * Atomically mark a token as used. Returns false if it was already used,
   * which is how two concurrent refreshes with the same token are caught
   * (in SQL: UPDATE ... SET used_at = ? WHERE token_hash = ? AND used_at IS NULL).
   */
  markUsed(tokenHash: string, at: number): Promise<boolean>;
}

export interface Repositories {
  users: UserRepository;
  sessions: SessionRepository;
  refreshTokens: RefreshTokenRepository;
}
