// In-memory implementation of the repositories. Good for tests and local
// dev; data is lost on restart. Objects are copied on the way in and out so
// callers can't mutate stored state by accident (a real DB behaves the same).

import type {
  RefreshTokenRecord,
  RefreshTokenRepository,
  Repositories,
  Session,
  SessionRepository,
  User,
  UserRepository,
} from "./repository.js";

class MemoryUsers implements UserRepository {
  private byId = new Map<string, User>();
  private idByEmail = new Map<string, string>();

  async create(user: User): Promise<void> {
    // Mirrors a UNIQUE(email) constraint.
    if (this.idByEmail.has(user.email)) throw new Error("UNIQUE constraint failed: users.email");
    this.byId.set(user.id, { ...user });
    this.idByEmail.set(user.email, user.id);
  }

  async findById(id: string): Promise<User | null> {
    const u = this.byId.get(id);
    return u ? { ...u } : null;
  }

  async findByEmail(email: string): Promise<User | null> {
    const id = this.idByEmail.get(email);
    return id ? this.findById(id) : null;
  }

  async update(id: string, patch: Partial<Omit<User, "id">>): Promise<void> {
    const u = this.byId.get(id);
    if (!u) throw new Error(`User ${id} not found`);
    this.byId.set(id, { ...u, ...patch });
  }
}

class MemorySessions implements SessionRepository {
  private rows = new Map<string, Session>();

  async create(session: Session): Promise<void> {
    this.rows.set(session.id, { ...session });
  }

  async findById(id: string): Promise<Session | null> {
    const s = this.rows.get(id);
    return s ? { ...s } : null;
  }

  async revoke(id: string, reason: NonNullable<Session["revokedReason"]>, at: number): Promise<void> {
    const s = this.rows.get(id);
    if (s && s.revokedAt === null) this.rows.set(id, { ...s, revokedAt: at, revokedReason: reason });
  }
}

class MemoryRefreshTokens implements RefreshTokenRepository {
  private rows = new Map<string, RefreshTokenRecord>();

  async create(record: RefreshTokenRecord): Promise<void> {
    this.rows.set(record.tokenHash, { ...record });
  }

  async findByHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
    const r = this.rows.get(tokenHash);
    return r ? { ...r } : null;
  }

  async markUsed(tokenHash: string, at: number): Promise<boolean> {
    // Single-threaded JS: check-and-set with no await in between is atomic.
    const r = this.rows.get(tokenHash);
    if (!r || r.usedAt !== null) return false;
    this.rows.set(tokenHash, { ...r, usedAt: at });
    return true;
  }
}

export function createMemoryRepositories(): Repositories {
  return {
    users: new MemoryUsers(),
    sessions: new MemorySessions(),
    refreshTokens: new MemoryRefreshTokens(),
  };
}
