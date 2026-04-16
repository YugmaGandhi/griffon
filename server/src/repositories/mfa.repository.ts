import { and, eq, sql } from 'drizzle-orm';
import { db } from '../db/connection';
import { mfaSettings, mfaRecoveryCodes, orgMfaPolicies } from '../db/schema';
import { MfaSetting, MfaRecoveryCode, OrgMfaPolicy } from '../utils/types';
import { createLogger } from '../utils/logger';

const log = createLogger('MfaRepository');

export class MfaRepository {
  // ── MFA Settings ──────────────────────────────────────

  // Create or replace the MFA setting row for a user.
  // Uses upsert so if a user abandons setup and starts again, the old
  // incomplete row is replaced cleanly instead of throwing a unique error.
  // isEnabled remains false until verifySetup() is called.
  async createSetting(
    userId: string,
    encryptedSecret: string
  ): Promise<MfaSetting> {
    log.debug({ userId }, 'Creating MFA setting');

    const [setting] = await db
      .insert(mfaSettings)
      .values({ userId, encryptedSecret })
      .onConflictDoUpdate({
        target: mfaSettings.userId,
        set: { encryptedSecret, isEnabled: false, enabledAt: null },
      })
      .returning();

    return setting;
  }

  // Get the MFA setting for a user — null if MFA has never been set up.
  async findByUserId(userId: string): Promise<MfaSetting | null> {
    const [setting] = await db
      .select()
      .from(mfaSettings)
      .where(eq(mfaSettings.userId, userId));

    return setting ?? null;
  }

  // Activate MFA after the user has successfully verified their first TOTP code.
  async enable(userId: string): Promise<void> {
    log.debug({ userId }, 'Enabling MFA');

    await db
      .update(mfaSettings)
      .set({ isEnabled: true, enabledAt: new Date() })
      .where(eq(mfaSettings.userId, userId));
  }

  // Remove the MFA setting row entirely.
  // Recovery codes are deleted automatically via ON DELETE CASCADE on userId.
  async deleteSetting(userId: string): Promise<void> {
    log.debug({ userId }, 'Deleting MFA setting');

    await db.delete(mfaSettings).where(eq(mfaSettings.userId, userId));
  }

  // ── Recovery Codes ────────────────────────────────────

  // Bulk-insert recovery code hashes for a user.
  // Called at enrollment and at regeneration (after old codes are deleted).
  // Single round-trip regardless of how many codes.
  async createRecoveryCodes(
    userId: string,
    codeHashes: string[]
  ): Promise<void> {
    log.debug({ userId, count: codeHashes.length }, 'Creating recovery codes');

    await db
      .insert(mfaRecoveryCodes)
      .values(codeHashes.map((codeHash) => ({ userId, codeHash })));
  }

  // Find a single recovery code row by userId + hash.
  // Returns null if the code doesn't exist or has already been used (deleted).
  async findRecoveryCode(
    userId: string,
    codeHash: string
  ): Promise<MfaRecoveryCode | null> {
    const [code] = await db
      .select()
      .from(mfaRecoveryCodes)
      .where(
        and(
          eq(mfaRecoveryCodes.userId, userId),
          eq(mfaRecoveryCodes.codeHash, codeHash)
        )
      );

    return code ?? null;
  }

  // Delete a single recovery code by ID.
  // Called immediately after a code is used — single-use enforced by deletion.
  async deleteRecoveryCode(id: string): Promise<void> {
    log.debug({ codeId: id }, 'Deleting used recovery code');

    await db.delete(mfaRecoveryCodes).where(eq(mfaRecoveryCodes.id, id));
  }

  // Delete all recovery codes for a user.
  // Called before generating a fresh set (regeneration flow).
  async deleteAllRecoveryCodes(userId: string): Promise<void> {
    log.debug({ userId }, 'Deleting all recovery codes');

    await db
      .delete(mfaRecoveryCodes)
      .where(eq(mfaRecoveryCodes.userId, userId));
  }

  // Count remaining recovery codes for a user.
  // Returned in the status response so users know when to regenerate.
  async countRecoveryCodes(userId: string): Promise<number> {
    const [result] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(mfaRecoveryCodes)
      .where(eq(mfaRecoveryCodes.userId, userId));

    return result?.count ?? 0;
  }

  // ── Org MFA Policies ──────────────────────────────────

  // Get the MFA policy for an org — null if no policy has been set
  // (which means MFA is not enforced, same as requireMfa = false).
  async findOrgPolicy(orgId: string): Promise<OrgMfaPolicy | null> {
    const [policy] = await db
      .select()
      .from(orgMfaPolicies)
      .where(eq(orgMfaPolicies.orgId, orgId));

    return policy ?? null;
  }

  // Create or update the MFA policy for an org.
  // enforcedAt is set to now when requireMfa flips to true, cleared when false.
  async upsertOrgPolicy(
    orgId: string,
    requireMfa: boolean
  ): Promise<OrgMfaPolicy> {
    log.debug({ orgId, requireMfa }, 'Upserting org MFA policy');

    const enforcedAt = requireMfa ? new Date() : null;

    const [policy] = await db
      .insert(orgMfaPolicies)
      .values({ orgId, requireMfa, enforcedAt })
      .onConflictDoUpdate({
        target: orgMfaPolicies.orgId,
        set: { requireMfa, enforcedAt, updatedAt: new Date() },
      })
      .returning();

    return policy;
  }
}

export const mfaRepository = new MfaRepository();
