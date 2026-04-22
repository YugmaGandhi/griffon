import { and, eq, gt, isNull, or, sql } from 'drizzle-orm';
import { db } from '../db/connection';
import { apiKeys } from '../db/schema';
import { ApiKey } from '../utils/types';
import { createLogger } from '../utils/logger';

const log = createLogger('ApiKeyRepository');

type CreateApiKeyParams = {
  userId: string;
  orgId?: string | null;
  name: string;
  prefix: string;
  keyHash: string;
  permissions: string[];
  expiresAt?: Date | null;
};

export class ApiKeyRepository {
  // Insert a new API key row. Returns the full row including id.
  // keyHash is SHA-256 of the raw key — plaintext never stored here.
  async create(params: CreateApiKeyParams): Promise<ApiKey> {
    log.debug({ userId: params.userId, name: params.name }, 'Creating API key');

    const [key] = await db
      .insert(apiKeys)
      .values({
        userId: params.userId,
        orgId: params.orgId ?? null,
        name: params.name,
        prefix: params.prefix,
        keyHash: params.keyHash,
        permissions: params.permissions,
        expiresAt: params.expiresAt ?? null,
      })
      .returning();

    return key;
  }

  // Lookup a key by its SHA-256 hash — used in the auth middleware hot path.
  // Returns revoked and expired keys too; validity checks are the service's job.
  async findByHash(keyHash: string): Promise<ApiKey | null> {
    const [key] = await db
      .select()
      .from(apiKeys)
      .where(eq(apiKeys.keyHash, keyHash));

    return key ?? null;
  }

  // Lookup a single key by its UUID — used for ownership checks in management endpoints.
  async findById(id: string): Promise<ApiKey | null> {
    const [key] = await db.select().from(apiKeys).where(eq(apiKeys.id, id));

    return key ?? null;
  }

  // List all non-revoked keys for a user, newest first.
  // Revoked rows are kept in the DB for audit purposes but excluded from the management view.
  async findByUserId(userId: string): Promise<ApiKey[]> {
    return db
      .select()
      .from(apiKeys)
      .where(and(eq(apiKeys.userId, userId), isNull(apiKeys.revokedAt)))
      .orderBy(sql`${apiKeys.createdAt} DESC`);
  }

  // Soft-revoke a key. Row is kept for audit history; the middleware rejects revokedAt IS NOT NULL.
  async revoke(id: string): Promise<void> {
    log.debug({ keyId: id }, 'Revoking API key');

    await db
      .update(apiKeys)
      .set({ revokedAt: new Date() })
      .where(eq(apiKeys.id, id));
  }

  // Fire-and-forget update — called on every authenticated request via the key.
  // Not awaited by the caller; errors are swallowed here to prevent unhandled
  // promise rejections from crashing the process. Failure is non-critical.
  async updateLastUsed(id: string): Promise<void> {
    try {
      await db
        .update(apiKeys)
        .set({ lastUsedAt: new Date() })
        .where(eq(apiKeys.id, id));
    } catch (err) {
      log.warn({ keyId: id, err }, 'Failed to update lastUsedAt');
    }
  }

  // Count active (non-revoked, non-expired) keys for a user — used to enforce MAX_API_KEYS_PER_USER.
  // Expired keys are excluded: they cannot authenticate, so they should not occupy a slot.
  async countByUserId(userId: string): Promise<number> {
    const [result] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(apiKeys)
      .where(
        and(
          eq(apiKeys.userId, userId),
          isNull(apiKeys.revokedAt),
          or(isNull(apiKeys.expiresAt), gt(apiKeys.expiresAt, new Date()))
        )
      );

    return result?.count ?? 0;
  }
}

export const apiKeyRepository = new ApiKeyRepository();
