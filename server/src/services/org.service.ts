import { orgRepository } from '../repositories/org.repository';
import { auditRepository } from '../repositories/audit.repository';
import { userRepository } from '../repositories/user.repository';
import { invitationRepository } from '../repositories/invitation.repository';
import {
  AuthError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
} from '../utils/errors';
import { Organization } from '../utils/types';
import { createLogger } from '../utils/logger';
import { env } from '../config/env';
import { seedOrgDefaults } from '../db/seed';
import { emailService } from './email.service';
import { webhookService } from './webhook.service';

const log = createLogger('OrgService');

// Slug must be URL-safe: lowercase letters, numbers, hyphens only
// No leading/trailing hyphens, no consecutive hyphens
const SLUG_REGEX = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

type CreateOrgParams = {
  name: string;
  slug: string;
  userId: string;
  userRoles: string[];
  ipAddress?: string;
  userAgent?: string;
};

type UpdateOrgParams = {
  orgId: string;
  name?: string;
  slug?: string;
  logoUrl?: string | null;
  metadata?: Record<string, unknown>;
  userId: string;
  ipAddress?: string;
  userAgent?: string;
};

export class OrgService {
  async create(params: CreateOrgParams): Promise<Organization> {
    const { name, slug, userId, userRoles, ipAddress, userAgent } = params;

    log.info({ slug, userId }, 'Creating organization');

    // Step 1 — Check if user is allowed to create orgs
    if (!env.ALLOW_ORG_CREATION && !userRoles.includes('super-admin')) {
      throw new ForbiddenError(
        'FORBIDDEN',
        'Organization creation is disabled. Contact a super-admin.'
      );
    }

    // Step 2 — Validate slug format
    if (!SLUG_REGEX.test(slug)) {
      throw new ConflictError(
        'INVALID_SLUG',
        'Slug must contain only lowercase letters, numbers, and hyphens'
      );
    }

    // Step 3 — Check org limit per user
    const count = await orgRepository.countByCreator(userId);
    if (count >= env.MAX_ORGS_PER_USER) {
      throw new ConflictError(
        'MAX_ORGS_REACHED',
        `You can create a maximum of ${env.MAX_ORGS_PER_USER} organizations`
      );
    }

    // Step 4 — Check slug uniqueness
    const existing = await orgRepository.findBySlug(slug);
    if (existing) {
      throw new ConflictError(
        'SLUG_ALREADY_EXISTS',
        'An organization with this slug already exists'
      );
    }

    // Step 5 — Create org
    const org = await orgRepository.create({
      name,
      slug,
      createdBy: userId,
    });

    // Step 6 — Seed default org roles + permissions
    await seedOrgDefaults(org.id);

    // Step 7 — Add creator as owner
    await orgRepository.addMember(org.id, userId, 'owner');

    // Step 8 — Audit log
    await auditRepository.create({
      userId,
      eventType: 'org_created',
      ipAddress,
      userAgent,
      metadata: { orgId: org.id, slug },
    });

    log.info({ orgId: org.id, slug }, 'Organization created');
    return org;
  }

  async list(userId: string) {
    return orgRepository.findByUserId(userId);
  }

  async getById(orgId: string): Promise<Organization> {
    const org = await orgRepository.findById(orgId);
    if (!org) {
      throw new NotFoundError('NOT_FOUND', 'Organization not found');
    }
    return org;
  }

  async update(params: UpdateOrgParams): Promise<Organization> {
    const { orgId, userId, ipAddress, userAgent, ...updates } = params;

    log.info({ orgId, userId }, 'Updating organization');

    // Check org exists
    const org = await orgRepository.findById(orgId);
    if (!org) {
      throw new NotFoundError('NOT_FOUND', 'Organization not found');
    }

    // Check membership + permission
    const membership = await orgRepository.findMembership(orgId, userId);
    if (!membership || !['owner', 'admin'].includes(membership.role)) {
      throw new ForbiddenError(
        'FORBIDDEN',
        'You do not have permission to update this organization'
      );
    }

    // If slug is being changed, validate format + uniqueness
    if (updates.slug !== undefined) {
      if (!SLUG_REGEX.test(updates.slug)) {
        throw new ConflictError(
          'INVALID_SLUG',
          'Slug must contain only lowercase letters, numbers, and hyphens'
        );
      }

      if (updates.slug !== org.slug) {
        const existing = await orgRepository.findBySlug(updates.slug);
        if (existing) {
          throw new ConflictError(
            'SLUG_ALREADY_EXISTS',
            'An organization with this slug already exists'
          );
        }
      }
    }

    // Build update payload — only include fields that were provided
    const updateData: Record<string, unknown> = {};
    if (updates.name !== undefined) updateData.name = updates.name;
    if (updates.slug !== undefined) updateData.slug = updates.slug;
    if (updates.logoUrl !== undefined) updateData.logoUrl = updates.logoUrl;
    if (updates.metadata !== undefined) updateData.metadata = updates.metadata;

    const updated = await orgRepository.update(orgId, updateData);

    await auditRepository.create({
      userId,
      eventType: 'org_updated',
      ipAddress,
      userAgent,
      metadata: { orgId, changes: Object.keys(updateData) },
    });

    log.info({ orgId }, 'Organization updated');
    return updated;
  }

  async delete(params: {
    orgId: string;
    userId: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<void> {
    const { orgId, userId, ipAddress, userAgent } = params;

    log.info({ orgId, userId }, 'Deleting organization');

    const org = await orgRepository.findById(orgId);
    if (!org) {
      throw new NotFoundError('NOT_FOUND', 'Organization not found');
    }

    // Only owner can delete
    const membership = await orgRepository.findMembership(orgId, userId);
    if (!membership || membership.role !== 'owner') {
      throw new ForbiddenError(
        'FORBIDDEN',
        'Only the organization owner can delete it'
      );
    }

    // Clear activeOrgId for any user who had this org active
    await userRepository.clearActiveOrg(orgId);

    await orgRepository.delete(orgId);

    await auditRepository.create({
      userId,
      eventType: 'org_deleted',
      ipAddress,
      userAgent,
      metadata: { orgId, slug: org.slug },
    });

    log.info({ orgId }, 'Organization deleted');
  }
  // ── Member Management ──────────────────────────────────

  async listMembers(orgId: string) {
    return orgRepository.listMembers(orgId);
  }

  async updateMemberRole(params: {
    orgId: string;
    targetUserId: string;
    newRole: string;
    actorUserId: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<void> {
    const { orgId, targetUserId, newRole, actorUserId, ipAddress, userAgent } =
      params;

    log.info({ orgId, targetUserId, newRole }, 'Updating member role');

    // Check target is a member
    const targetMembership = await orgRepository.findMembership(
      orgId,
      targetUserId
    );
    if (!targetMembership) {
      throw new NotFoundError('NOT_FOUND', 'Member not found in organization');
    }

    // Check actor's membership
    const actorMembership = await orgRepository.findMembership(
      orgId,
      actorUserId
    );
    if (!actorMembership) {
      throw new ForbiddenError(
        'FORBIDDEN',
        'You are not a member of this organization'
      );
    }

    // Role hierarchy enforcement
    const ROLE_RANK: Record<string, number> = {
      owner: 3,
      admin: 2,
      member: 1,
    };

    const actorRank = ROLE_RANK[actorMembership.role] ?? 0;
    const targetCurrentRank = ROLE_RANK[targetMembership.role] ?? 0;
    const targetNewRank = ROLE_RANK[newRole] ?? 0;

    // Can't change someone at or above your level
    if (targetCurrentRank >= actorRank) {
      throw new ForbiddenError(
        'FORBIDDEN',
        'You cannot change the role of a member with equal or higher rank'
      );
    }

    // Can't promote someone to or above your level
    if (targetNewRank >= actorRank) {
      throw new ForbiddenError(
        'FORBIDDEN',
        'You cannot promote a member to your rank or higher'
      );
    }

    await orgRepository.updateMemberRole(orgId, targetUserId, newRole);

    await auditRepository.create({
      userId: actorUserId,
      eventType: 'org_member_role_changed',
      ipAddress,
      userAgent,
      metadata: {
        orgId,
        targetUserId,
        oldRole: targetMembership.role,
        newRole,
      },
    });

    log.info({ orgId, targetUserId, newRole }, 'Member role updated');
  }

  async removeMember(params: {
    orgId: string;
    targetUserId: string;
    actorUserId: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<void> {
    const { orgId, targetUserId, actorUserId, ipAddress, userAgent } = params;

    log.info({ orgId, targetUserId }, 'Removing member');

    const targetMembership = await orgRepository.findMembership(
      orgId,
      targetUserId
    );
    if (!targetMembership) {
      throw new NotFoundError('NOT_FOUND', 'Member not found in organization');
    }

    // Can't remove the last owner
    if (targetMembership.role === 'owner') {
      const ownerCount = await orgRepository.countOwners(orgId);
      if (ownerCount <= 1) {
        throw new ForbiddenError(
          'FORBIDDEN',
          'Cannot remove the last owner. Transfer ownership first.'
        );
      }
    }

    // If removing yourself, always allowed (except last owner, handled above)
    if (targetUserId !== actorUserId) {
      const actorMembership = await orgRepository.findMembership(
        orgId,
        actorUserId
      );
      if (!actorMembership) {
        throw new ForbiddenError(
          'FORBIDDEN',
          'You are not a member of this organization'
        );
      }

      const ROLE_RANK: Record<string, number> = {
        owner: 3,
        admin: 2,
        member: 1,
      };

      // Can't remove someone at or above your level
      if (
        (ROLE_RANK[targetMembership.role] ?? 0) >=
        (ROLE_RANK[actorMembership.role] ?? 0)
      ) {
        throw new ForbiddenError(
          'FORBIDDEN',
          'You cannot remove a member with equal or higher rank'
        );
      }
    }

    // Clear activeOrgId if the removed user had this org active
    if (targetUserId !== actorUserId) {
      const user = await userRepository.findById(targetUserId);
      if (user && user.activeOrgId === orgId) {
        await userRepository.clearActiveOrgForUser(targetUserId);
      }
    }

    await orgRepository.removeMember(orgId, targetUserId);

    await auditRepository.create({
      userId: actorUserId,
      eventType: 'org_member_removed',
      ipAddress,
      userAgent,
      metadata: { orgId, targetUserId, role: targetMembership.role },
    });

    void webhookService
      .fanout({
        eventType: 'org.member.removed',
        orgId,
        payload: { orgId, userId: targetUserId, role: targetMembership.role },
      })
      .catch((err: unknown) => log.error({ err }, 'Webhook fanout failed'));

    log.info({ orgId, targetUserId }, 'Member removed');
  }

  // ── Invitations ───────────────────────────────────────

  async inviteMember(params: {
    orgId: string;
    email: string;
    role: string;
    invitedByUserId: string;
    invitedByEmail: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<void> {
    const {
      orgId,
      email,
      role,
      invitedByUserId,
      invitedByEmail,
      ipAddress,
      userAgent,
    } = params;

    log.info({ orgId, email, role }, 'Inviting member');

    // Check org exists
    const org = await orgRepository.findById(orgId);
    if (!org) {
      throw new NotFoundError('NOT_FOUND', 'Organization not found');
    }

    // Check if already a member
    const existingUser = await userRepository.findByEmail(email);
    if (existingUser) {
      const membership = await orgRepository.findMembership(
        orgId,
        existingUser.id
      );
      if (membership) {
        throw new ConflictError(
          'ALREADY_MEMBER',
          'This user is already a member of the organization'
        );
      }
    }

    // Check for existing pending invitation
    const pendingInvite = await invitationRepository.findPending(orgId, email);
    if (pendingInvite) {
      throw new ConflictError(
        'INVITATION_PENDING',
        'A pending invitation already exists for this email'
      );
    }

    // Create invitation token
    const rawToken = await invitationRepository.create({
      orgId,
      email,
      role,
      invitedBy: invitedByUserId,
    });

    // Send invitation email — fire and forget
    void emailService.sendOrgInvitationEmail({
      email,
      token: rawToken,
      orgName: org.name,
      invitedByEmail,
      role,
    });

    await auditRepository.create({
      userId: invitedByUserId,
      eventType: 'org_member_invited',
      ipAddress,
      userAgent,
      metadata: { orgId, email, role },
    });

    log.info({ orgId, email }, 'Invitation sent');
  }

  async acceptInvitation(params: {
    token: string;
    userId: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<{
    orgId: string;
    orgName: string;
    orgSlug: string;
    role: string;
  }> {
    const { token, userId, ipAddress, userAgent } = params;

    log.info({ userId }, 'Accepting invitation');

    // Find valid invitation
    const invitation = await invitationRepository.findByToken(token);
    if (!invitation) {
      throw new AuthError(
        'TOKEN_INVALID',
        'This invitation is invalid, expired, or has already been used',
        400
      );
    }

    // Check if already a member
    const existingMembership = await orgRepository.findMembership(
      invitation.orgId,
      userId
    );
    if (existingMembership) {
      throw new ConflictError(
        'ALREADY_MEMBER',
        'You are already a member of this organization'
      );
    }

    // Add as member with the role specified in the invitation
    await orgRepository.addMember(invitation.orgId, userId, invitation.role);

    // Mark invitation as accepted
    await invitationRepository.markAccepted(invitation.id);

    // Get org details for response
    const org = await orgRepository.findById(invitation.orgId);

    await auditRepository.create({
      userId,
      eventType: 'org_member_joined',
      ipAddress,
      userAgent,
      metadata: {
        orgId: invitation.orgId,
        role: invitation.role,
        invitationId: invitation.id,
      },
    });

    void webhookService
      .fanout({
        eventType: 'org.member.joined',
        orgId: invitation.orgId,
        payload: { orgId: invitation.orgId, userId, role: invitation.role },
      })
      .catch((err: unknown) => log.error({ err }, 'Webhook fanout failed'));

    log.info(
      { orgId: invitation.orgId, userId, role: invitation.role },
      'Invitation accepted'
    );

    return {
      orgId: invitation.orgId,
      orgName: org!.name,
      orgSlug: org!.slug,
      role: invitation.role,
    };
  }

  async transferOwnership(params: {
    orgId: string;
    newOwnerId: string;
    actorUserId: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<void> {
    const { orgId, newOwnerId, actorUserId, ipAddress, userAgent } = params;

    log.info({ orgId, newOwnerId, actorUserId }, 'Transferring ownership');

    // Check org exists
    const org = await orgRepository.findById(orgId);
    if (!org) {
      throw new NotFoundError('NOT_FOUND', 'Organization not found');
    }

    // Caller must be owner
    const actorMembership = await orgRepository.findMembership(
      orgId,
      actorUserId
    );
    if (!actorMembership || actorMembership.role !== 'owner') {
      throw new ForbiddenError(
        'FORBIDDEN',
        'Only the organization owner can transfer ownership'
      );
    }

    // Can't transfer to yourself
    if (newOwnerId === actorUserId) {
      throw new ConflictError(
        'INVALID_TRANSFER',
        'You are already the owner of this organization'
      );
    }

    // New owner must be an existing member
    const newOwnerMembership = await orgRepository.findMembership(
      orgId,
      newOwnerId
    );
    if (!newOwnerMembership) {
      throw new NotFoundError(
        'NOT_FOUND',
        'The specified user is not a member of this organization'
      );
    }

    // Atomic swap: promote new owner, demote current owner to admin
    await orgRepository.transferOwnership(orgId, newOwnerId, actorUserId);

    await auditRepository.create({
      userId: actorUserId,
      eventType: 'org_member_role_changed',
      ipAddress,
      userAgent,
      metadata: { orgId, newOwnerId, previousOwner: actorUserId },
    });

    log.info({ orgId, newOwnerId }, 'Ownership transferred');
  }

  async listInvitations(orgId: string) {
    return invitationRepository.listPending(orgId);
  }

  async revokeInvitation(params: {
    orgId: string;
    invitationId: string;
    userId: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<void> {
    const { orgId, invitationId, userId, ipAddress, userAgent } = params;

    const invitation = await invitationRepository.findById(invitationId);
    if (!invitation || invitation.orgId !== orgId) {
      throw new NotFoundError('NOT_FOUND', 'Invitation not found');
    }

    if (invitation.status !== 'pending') {
      throw new ConflictError(
        'INVITATION_NOT_PENDING',
        'Only pending invitations can be revoked'
      );
    }

    await invitationRepository.revoke(invitationId);

    await auditRepository.create({
      userId,
      eventType: 'org_member_invited',
      ipAddress,
      userAgent,
      metadata: {
        orgId,
        invitationId,
        action: 'revoked',
        email: invitation.email,
      },
    });

    log.info({ orgId, invitationId }, 'Invitation revoked');
  }
}

export const orgService = new OrgService();
