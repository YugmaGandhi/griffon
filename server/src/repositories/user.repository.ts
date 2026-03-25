import { eq, sql, and } from 'drizzle-orm';
import { db } from '../db/connection';
import { users } from '../db/schema';
import { NewUser, User, SafeUser, toSafeUser } from '../utils/types';
import { createLogger } from '../utils/logger';

const log = createLogger('UserRepository');

export class UserRepository {
  // ── Create ────────────────────────────────────────────
  async create(data: NewUser): Promise<SafeUser> {
    log.debug({ email: data.email }, 'Creating user');

    const [user] = await db.insert(users).values(data).returning();

    // Never return passwordHash from repository
    return toSafeUser(user);
  }

  // ── Find by Email ─────────────────────────────────────
  // Returns full user including passwordHash
  // Only used internally for auth — never sent to client
  async findByEmail(email: string): Promise<User | null> {
    log.debug({ email }, 'Finding user by email');

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email.toLowerCase().trim()));

    return user ?? null;
  }

  // ── Find by ID ────────────────────────────────────────
  async findById(id: string): Promise<SafeUser | null> {
    log.debug({ userId: id }, 'Finding user by ID');

    const [user] = await db.select().from(users).where(eq(users.id, id));

    if (!user) return null;
    return toSafeUser(user);
  }

  // ── Update Failed Attempts ────────────────────────────
  async incrementFailedAttempts(id: string): Promise<void> {
    await db
      .update(users)
      .set({
        failedAttempts: sql`${users.failedAttempts} + 1`,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id));
  }

  // ── Lock Account ──────────────────────────────────────
  async lockAccount(id: string, until: Date): Promise<void> {
    log.warn({ userId: id, until }, 'Locking account');

    await db
      .update(users)
      .set({
        isLocked: true,
        lockedUntil: until,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id));
  }

  // ── Reset Failed Attempts ─────────────────────────────
  async resetFailedAttempts(id: string): Promise<void> {
    await db
      .update(users)
      .set({
        failedAttempts: 0,
        isLocked: false,
        lockedUntil: null,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id));
  }

  // ── Mark Email Verified ───────────────────────────────
  async markEmailVerified(id: string): Promise<void> {
    log.info({ userId: id }, 'Marking email as verified');

    await db
      .update(users)
      .set({
        isVerified: true,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id));
  }

  // ── Update Password ───────────────────────────────────
  async updatePassword(id: string, passwordHash: string): Promise<void> {
    log.info({ userId: id }, 'Updating password');

    await db
      .update(users)
      .set({
        passwordHash,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id));
  }

  // ── Update Last Login ─────────────────────────────────
  async updateLastLogin(id: string): Promise<void> {
    await db
      .update(users)
      .set({ lastLoginAt: new Date(), updatedAt: new Date() })
      .where(eq(users.id, id));
  }

  // ── Find by OAuth ID ──────────────────────────────────────
  async findByOAuthId(
    provider: string,
    oauthId: string
  ): Promise<SafeUser | null> {
    const [user] = await db
      .select()
      .from(users)
      .where(
        and(eq(users.oauthProvider, provider), eq(users.oauthId, oauthId))
      );

    if (!user) return null;
    return toSafeUser(user);
  }

  // ── Create OAuth User ─────────────────────────────────────
  async createOAuthUser(data: {
    email: string;
    oauthProvider: string;
    oauthId: string;
    isVerified: boolean;
  }): Promise<SafeUser> {
    const [user] = await db
      .insert(users)
      .values({
        email: data.email,
        oauthProvider: data.oauthProvider,
        oauthId: data.oauthId,
        isVerified: data.isVerified,
        passwordHash: null,
      })
      .returning();

    return toSafeUser(user);
  }

  // ── Link OAuth to existing account ────────────────────────
  async linkOAuth(
    id: string,
    oauthProvider: string,
    oauthId: string
  ): Promise<void> {
    await db
      .update(users)
      .set({ oauthProvider, oauthId, updatedAt: new Date() })
      .where(eq(users.id, id));
  }
}

// Export a singleton instance
// The whole app shares one instance — no need to instantiate per request
export const userRepository = new UserRepository();
