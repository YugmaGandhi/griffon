import { eq, and } from 'drizzle-orm';
import crypto from 'crypto';
import { db } from '../db/connection';
import { orgInvitations } from '../db/schema';
import { createLogger } from '../utils/logger';

const log = createLogger('InvitationRepository');

export class InvitationRepository {
  // ── Create invitation ─────────────────────────────────
  async create(params: {
    orgId: string;
    email: string;
    role: string;
    invitedBy: string;
    expiryDays?: number;
  }): Promise<string> {
    const { orgId, email, role, invitedBy, expiryDays = 7 } = params;

    // Generate raw token — sent in the email
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiryDays);

    await db.insert(orgInvitations).values({
      orgId,
      email: email.toLowerCase().trim(),
      role,
      invitedBy,
      tokenHash,
      expiresAt,
    });

    log.debug({ orgId, email }, 'Invitation created');

    // Return raw token — only time it exists in plain text
    return rawToken;
  }

  // ── Find pending invitation by email + org ────────────
  async findPending(
    orgId: string,
    email: string
  ): Promise<{ id: string } | null> {
    const [row] = await db
      .select({ id: orgInvitations.id })
      .from(orgInvitations)
      .where(
        and(
          eq(orgInvitations.orgId, orgId),
          eq(orgInvitations.email, email.toLowerCase().trim()),
          eq(orgInvitations.status, 'pending')
        )
      );

    return row ?? null;
  }

  // ── Find valid invitation by raw token ────────────────
  async findByToken(rawToken: string) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    const [invitation] = await db
      .select()
      .from(orgInvitations)
      .where(
        and(
          eq(orgInvitations.tokenHash, tokenHash),
          eq(orgInvitations.status, 'pending')
        )
      );

    if (!invitation) return null;

    // Check expiry
    if (invitation.expiresAt < new Date()) {
      // Mark as expired
      await db
        .update(orgInvitations)
        .set({ status: 'expired' })
        .where(eq(orgInvitations.id, invitation.id));
      return null;
    }

    return invitation;
  }

  // ── Mark as accepted ──────────────────────────────────
  async markAccepted(id: string): Promise<void> {
    await db
      .update(orgInvitations)
      .set({ status: 'accepted', acceptedAt: new Date() })
      .where(eq(orgInvitations.id, id));
  }

  // ── Revoke invitation ─────────────────────────────────
  async revoke(id: string): Promise<void> {
    await db
      .update(orgInvitations)
      .set({ status: 'revoked' })
      .where(eq(orgInvitations.id, id));
  }

  // ── Find by ID ────────────────────────────────────────
  async findById(id: string) {
    const [invitation] = await db
      .select()
      .from(orgInvitations)
      .where(eq(orgInvitations.id, id));

    return invitation ?? null;
  }

  // ── List pending for an org ───────────────────────────
  async listPending(orgId: string) {
    return db
      .select()
      .from(orgInvitations)
      .where(
        and(
          eq(orgInvitations.orgId, orgId),
          eq(orgInvitations.status, 'pending')
        )
      );
  }
}

export const invitationRepository = new InvitationRepository();
