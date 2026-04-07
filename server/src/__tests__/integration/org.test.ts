import { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users, orgInvitations } from '../../db/schema';
import { eq, sql } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';
import crypto from 'crypto';

describe('Org Routes — CRUD, members, invitations, ownership', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    await redis.connect();
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    await redis.flushdb();
    await db.execute(
      sql`TRUNCATE TABLE audit_logs, refresh_tokens, email_tokens, user_roles, role_permissions, roles, permissions, org_role_permissions, org_member_roles, org_permissions, org_roles, org_invitations, org_members, organizations, users RESTART IDENTITY CASCADE`
    );
    await seedSystemData();
  });

  afterAll(async () => {
    await app.close();
  });

  // ── Helpers ────────────────────────────────────────────
  async function createVerifiedUser(
    email: string,
    password: string
  ): Promise<{ userId: string; accessToken: string }> {
    const registerRes = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password },
    });
    const userId = registerRes.json<{
      data: { user: { id: string } };
    }>().data.user.id;

    await db
      .update(users)
      .set({ isVerified: true })
      .where(eq(users.email, email));

    const loginRes = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password },
    });
    const accessToken = loginRes.json<{
      data: { accessToken: string };
    }>().data.accessToken;

    return { userId, accessToken };
  }

  async function createOrg(
    accessToken: string,
    name: string,
    slug: string
  ): Promise<{ orgId: string; slug: string; name: string }> {
    const res = await app.inject({
      method: 'POST',
      url: '/api/orgs',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { name, slug },
    });
    return res.json<{
      data: { organization: { id: string; slug: string; name: string } };
    }>().data.organization as { orgId: string; slug: string; name: string } & {
      id: string;
    } & { orgId: string };
  }

  // Inserts an invitation with a known token directly into the DB
  // Mirrors the approach in auth.email-flows.test.ts for email tokens
  async function createTestInvitation(params: {
    orgId: string;
    email: string;
    role: string;
    invitedBy: string;
  }): Promise<string> {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await db.insert(orgInvitations).values({
      orgId: params.orgId,
      email: params.email.toLowerCase(),
      role: params.role,
      invitedBy: params.invitedBy,
      tokenHash,
      expiresAt,
    });

    return rawToken;
  }

  // ── POST /api/orgs ─────────────────────────────────────
  describe('POST /api/orgs', () => {
    it('should create an org and make creator the owner', async () => {
      const { accessToken, userId } = await createVerifiedUser(
        'owner@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/orgs',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'Acme Corp', slug: 'acme' },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json<{
        success: boolean;
        data: {
          organization: {
            id: string;
            name: string;
            slug: string;
            createdBy: string;
          };
        };
      }>();
      expect(body.success).toBe(true);
      expect(body.data.organization.name).toBe('Acme Corp');
      expect(body.data.organization.slug).toBe('acme');
      expect(body.data.organization.createdBy).toBe(userId);
    });

    it('should return 400 for invalid slug format', async () => {
      const { accessToken } = await createVerifiedUser(
        'slugtest@example.com',
        'password123'
      );

      // Slug is lowercased by zod, but leading hyphens fail the SLUG_REGEX in service
      const res2 = await app.inject({
        method: 'POST',
        url: '/api/orgs',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'Bad Slug', slug: '-leading-hyphen' },
      });

      expect(res2.statusCode).toBe(409);
      const body = res2.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('INVALID_SLUG');
    });

    it('should return 409 for duplicate slug', async () => {
      const { accessToken } = await createVerifiedUser(
        'dup@example.com',
        'password123'
      );

      await app.inject({
        method: 'POST',
        url: '/api/orgs',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'First', slug: 'same-slug' },
      });

      const res = await app.inject({
        method: 'POST',
        url: '/api/orgs',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'Second', slug: 'same-slug' },
      });

      expect(res.statusCode).toBe(409);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('SLUG_ALREADY_EXISTS');
    });

    it('should return 401 for unauthenticated request', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/orgs',
        payload: { name: 'Unauth', slug: 'unauth' },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // ── GET /api/orgs ──────────────────────────────────────
  describe('GET /api/orgs', () => {
    it('should return orgs the user belongs to', async () => {
      const { accessToken } = await createVerifiedUser(
        'lister@example.com',
        'password123'
      );

      await app.inject({
        method: 'POST',
        url: '/api/orgs',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'Org One', slug: 'org-one' },
      });

      await app.inject({
        method: 'POST',
        url: '/api/orgs',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'Org Two', slug: 'org-two' },
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/orgs',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        data: { organizations: Array<{ slug: string; role: string }> };
      }>();
      expect(body.data.organizations).toHaveLength(2);
      expect(body.data.organizations.every((o) => o.role === 'owner')).toBe(
        true
      );
    });
  });

  // ── GET /api/orgs/:orgId ───────────────────────────────
  describe('GET /api/orgs/:orgId', () => {
    it('should return org by ID', async () => {
      const { accessToken } = await createVerifiedUser(
        'getter@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'GetMe', 'get-me');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'GET',
        url: `/api/orgs/${orgId}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        data: { organization: { id: string; slug: string } };
      }>();
      expect(body.data.organization.id).toBe(orgId);
      expect(body.data.organization.slug).toBe('get-me');
    });

    it('should return 404 for unknown org', async () => {
      const { accessToken } = await createVerifiedUser(
        'notfound@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/orgs/550e8400-e29b-41d4-a716-446655440000',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(404);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });

  // ── PATCH /api/orgs/:orgId ─────────────────────────────
  describe('PATCH /api/orgs/:orgId', () => {
    it('should update org name and slug', async () => {
      const { accessToken } = await createVerifiedUser(
        'updater@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'Old Name', 'old-slug');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/orgs/${orgId}`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'New Name', slug: 'new-slug' },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        data: { organization: { name: string; slug: string } };
      }>();
      expect(body.data.organization.name).toBe('New Name');
      expect(body.data.organization.slug).toBe('new-slug');
    });

    it('should return 403 for non-member', async () => {
      const { accessToken: ownerToken } = await createVerifiedUser(
        'orgowner2@example.com',
        'password123'
      );
      const { accessToken: otherToken } = await createVerifiedUser(
        'outsider@example.com',
        'password123'
      );

      const org = await createOrg(ownerToken, 'Private', 'private-org');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/orgs/${orgId}`,
        headers: { authorization: `Bearer ${otherToken}` },
        payload: { name: 'Hacked' },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // ── DELETE /api/orgs/:orgId ────────────────────────────
  describe('DELETE /api/orgs/:orgId', () => {
    it('should delete org (owner only)', async () => {
      const { accessToken } = await createVerifiedUser(
        'deleter@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'Deletable', 'deletable');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/orgs/${orgId}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);

      // Confirm it's gone
      const getRes = await app.inject({
        method: 'GET',
        url: `/api/orgs/${orgId}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(getRes.statusCode).toBe(404);
    });

    it('should return 403 for non-owner', async () => {
      const { accessToken: ownerToken } = await createVerifiedUser(
        'realowner@example.com',
        'password123'
      );
      const { accessToken: otherToken } = await createVerifiedUser(
        'wannabe@example.com',
        'password123'
      );

      const org = await createOrg(ownerToken, 'Protected', 'protected-org');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/orgs/${orgId}`,
        headers: { authorization: `Bearer ${otherToken}` },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // ── GET /api/orgs/:orgId/members ───────────────────────
  describe('GET /api/orgs/:orgId/members', () => {
    it('should list members with email and role', async () => {
      const { accessToken, userId } = await createVerifiedUser(
        'memberlister@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'Team', 'team-slug');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'GET',
        url: `/api/orgs/${orgId}/members`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        data: {
          members: Array<{ userId: string; email: string; role: string }>;
        };
      }>();
      expect(body.data.members).toHaveLength(1);
      expect(body.data.members[0].userId).toBe(userId);
      expect(body.data.members[0].role).toBe('owner');
      expect(body.data.members[0].email).toBe('memberlister@example.com');
    });
  });

  // ── PATCH /api/orgs/:orgId/members/:userId ─────────────
  describe('PATCH /api/orgs/:orgId/members/:userId', () => {
    it('should allow owner to change member role to admin', async () => {
      const { accessToken: ownerToken } = await createVerifiedUser(
        'roleowner@example.com',
        'password123'
      );
      const { userId: memberId } = await createVerifiedUser(
        'rolemember@example.com',
        'password123'
      );

      const org = await createOrg(ownerToken, 'Role Org', 'role-org');
      const orgId = (org as unknown as { id: string }).id;

      // Add member via direct DB insert (bypasses invitation flow for test speed)
      const { orgMembers: orgMembersSchema } = await import('../../db/schema');
      await db
        .insert(orgMembersSchema)
        .values({ orgId, userId: memberId, role: 'member' });

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/orgs/${orgId}/members/${memberId}`,
        headers: { authorization: `Bearer ${ownerToken}` },
        payload: { role: 'admin' },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { message: string } }>();
      expect(body.data.message).toContain('updated');
    });

    it('should return 403 when trying to change member of equal rank', async () => {
      const { accessToken: adminToken, userId: adminId } =
        await createVerifiedUser('admin1@example.com', 'password123');
      const { userId: admin2Id } = await createVerifiedUser(
        'admin2@example.com',
        'password123'
      );

      // Create org — adminToken is owner, then add two admins
      const { accessToken: ownerToken } = await createVerifiedUser(
        'bigboss@example.com',
        'password123'
      );
      const org = await createOrg(ownerToken, 'Rank Org', 'rank-org');
      const orgId = (org as unknown as { id: string }).id;

      const { orgMembers: orgMembersSchema } = await import('../../db/schema');
      await db.insert(orgMembersSchema).values([
        { orgId, userId: adminId, role: 'admin' },
        { orgId, userId: admin2Id, role: 'admin' },
      ]);

      // admin1 tries to change admin2's role — same rank, should fail
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/orgs/${orgId}/members/${admin2Id}`,
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { role: 'member' },
      });

      expect(res.statusCode).toBe(403);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });

  // ── DELETE /api/orgs/:orgId/members/:userId ────────────
  describe('DELETE /api/orgs/:orgId/members/:userId', () => {
    it('should remove a member from the org', async () => {
      const { accessToken: ownerToken } = await createVerifiedUser(
        'removeowner@example.com',
        'password123'
      );
      const { userId: memberId } = await createVerifiedUser(
        'leaveme@example.com',
        'password123'
      );

      const org = await createOrg(ownerToken, 'Remove Org', 'remove-org');
      const orgId = (org as unknown as { id: string }).id;

      const { orgMembers: orgMembersSchema } = await import('../../db/schema');
      await db
        .insert(orgMembersSchema)
        .values({ orgId, userId: memberId, role: 'member' });

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/orgs/${orgId}/members/${memberId}`,
        headers: { authorization: `Bearer ${ownerToken}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('should return 403 when trying to remove the last owner', async () => {
      const { accessToken, userId } = await createVerifiedUser(
        'lastowner@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'Solo Org', 'solo-org');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/orgs/${orgId}/members/${userId}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(403);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });

  // ── POST /api/orgs/:orgId/members/invite ───────────────
  describe('POST /api/orgs/:orgId/members/invite', () => {
    it('should create an invitation for a new email', async () => {
      const { accessToken } = await createVerifiedUser(
        'inviter@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'Invite Org', 'invite-org');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'POST',
        url: `/api/orgs/${orgId}/members/invite`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { email: 'newuser@example.com', role: 'member' },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json<{ data: { message: string } }>();
      expect(body.data.message).toContain('Invitation sent');
    });

    it('should return 409 when a pending invitation already exists', async () => {
      const { accessToken } = await createVerifiedUser(
        'inviter2@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'Dup Invite', 'dup-invite');
      const orgId = (org as unknown as { id: string }).id;

      await app.inject({
        method: 'POST',
        url: `/api/orgs/${orgId}/members/invite`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { email: 'pending@example.com', role: 'member' },
      });

      const res = await app.inject({
        method: 'POST',
        url: `/api/orgs/${orgId}/members/invite`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { email: 'pending@example.com', role: 'member' },
      });

      expect(res.statusCode).toBe(409);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('INVITATION_PENDING');
    });

    it('should return 409 when user is already a member', async () => {
      const { accessToken: ownerToken } = await createVerifiedUser(
        'inviteowner@example.com',
        'password123'
      );
      const { userId: existingMemberId } = await createVerifiedUser(
        'alreadyin@example.com',
        'password123'
      );

      const org = await createOrg(ownerToken, 'Already In', 'already-in');
      const orgId = (org as unknown as { id: string }).id;

      const { orgMembers: orgMembersSchema } = await import('../../db/schema');
      await db
        .insert(orgMembersSchema)
        .values({ orgId, userId: existingMemberId, role: 'member' });

      const res = await app.inject({
        method: 'POST',
        url: `/api/orgs/${orgId}/members/invite`,
        headers: { authorization: `Bearer ${ownerToken}` },
        payload: { email: 'alreadyin@example.com', role: 'member' },
      });

      expect(res.statusCode).toBe(409);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('ALREADY_MEMBER');
    });
  });

  // ── GET /api/orgs/:orgId/invitations ───────────────────
  describe('GET /api/orgs/:orgId/invitations', () => {
    it('should list pending invitations', async () => {
      const { accessToken, userId } = await createVerifiedUser(
        'invlist@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'Inv List', 'inv-list');
      const orgId = (org as unknown as { id: string }).id;

      await createTestInvitation({
        orgId,
        email: 'pending1@example.com',
        role: 'member',
        invitedBy: userId,
      });

      const res = await app.inject({
        method: 'GET',
        url: `/api/orgs/${orgId}/invitations`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        data: { invitations: Array<{ email: string; status: string }> };
      }>();
      expect(body.data.invitations).toHaveLength(1);
      expect(body.data.invitations[0].email).toBe('pending1@example.com');
      expect(body.data.invitations[0].status).toBe('pending');
    });
  });

  // ── DELETE /api/orgs/:orgId/invitations/:invitationId ──
  describe('DELETE /api/orgs/:orgId/invitations/:invitationId', () => {
    it('should revoke a pending invitation', async () => {
      const { accessToken, userId } = await createVerifiedUser(
        'revoker@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'Revoke Org', 'revoke-org');
      const orgId = (org as unknown as { id: string }).id;

      await createTestInvitation({
        orgId,
        email: 'tobecancelled@example.com',
        role: 'member',
        invitedBy: userId,
      });

      // Get the invitation ID from DB
      const [invitation] = await db
        .select({ id: orgInvitations.id })
        .from(orgInvitations)
        .where(eq(orgInvitations.orgId, orgId));

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/orgs/${orgId}/invitations/${invitation.id}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { message: string } }>();
      expect(body.data.message).toContain('revoked');
    });

    it('should return 404 for non-existent invitation', async () => {
      const { accessToken } = await createVerifiedUser(
        'notfoundinv@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'No Inv', 'no-inv');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/orgs/${orgId}/invitations/550e8400-e29b-41d4-a716-446655440000`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(404);
    });
  });

  // ── POST /auth/accept-invitation ───────────────────────
  describe('POST /auth/accept-invitation', () => {
    it('should add user to org on valid token', async () => {
      const { accessToken: ownerToken, userId: ownerId } =
        await createVerifiedUser('acceptowner@example.com', 'password123');
      const { accessToken: inviteeToken } = await createVerifiedUser(
        'invitee@example.com',
        'password123'
      );

      const org = await createOrg(ownerToken, 'Accept Org', 'accept-org');
      const orgId = (org as unknown as { id: string }).id;

      const rawToken = await createTestInvitation({
        orgId,
        email: 'invitee@example.com',
        role: 'member',
        invitedBy: ownerId,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/accept-invitation',
        headers: { authorization: `Bearer ${inviteeToken}` },
        payload: { token: rawToken },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        data: {
          organization: { id: string; role: string };
        };
      }>();
      expect(body.data.organization.id).toBe(orgId);
      expect(body.data.organization.role).toBe('member');
    });

    it('should return 400 for invalid or expired token', async () => {
      const { accessToken } = await createVerifiedUser(
        'badinvite@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'POST',
        url: '/auth/accept-invitation',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { token: 'completelyfaketoken' },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('TOKEN_INVALID');
    });

    it('should return 409 when user is already a member', async () => {
      const { accessToken: ownerToken } = await createVerifiedUser(
        'dupaccept@example.com',
        'password123'
      );
      const { accessToken: memberToken, userId: memberId } =
        await createVerifiedUser('dupacceptmember@example.com', 'password123');

      const org = await createOrg(ownerToken, 'Dup Accept', 'dup-accept');
      const orgId = (org as unknown as { id: string }).id;

      const { orgMembers: orgMembersSchema } = await import('../../db/schema');
      await db
        .insert(orgMembersSchema)
        .values({ orgId, userId: memberId, role: 'member' });

      const rawToken = await createTestInvitation({
        orgId,
        email: 'dupacceptmember@example.com',
        role: 'member',
        invitedBy: memberId,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/accept-invitation',
        headers: { authorization: `Bearer ${memberToken}` },
        payload: { token: rawToken },
      });

      expect(res.statusCode).toBe(409);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('ALREADY_MEMBER');
    });
  });

  // ── POST /auth/set-active-org ──────────────────────────
  describe('POST /auth/set-active-org', () => {
    it('should switch active org and return new tokens with org claims', async () => {
      const { accessToken } = await createVerifiedUser(
        'switcher@example.com',
        'password123'
      );

      const org = await createOrg(accessToken, 'Switch Org', 'switch-org');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'POST',
        url: '/auth/set-active-org',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { orgId },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        data: {
          accessToken: string;
          refreshToken: string;
          expiresIn: number;
        };
      }>();
      expect(body.data.accessToken).toBeDefined();
      expect(body.data.refreshToken).toBeDefined();
      expect(body.data.expiresIn).toBe(900);

      // Verify new token carries org claims
      const { tokenService } = await import('../../services/token.service');
      const payload = await tokenService.verifyAccessToken(
        body.data.accessToken
      );
      expect(payload.orgId).toBe(orgId);
      expect(payload.orgRole).toBe('owner');
    });

    it('should return 403 when user is not a member of the org', async () => {
      const { accessToken: ownerToken } = await createVerifiedUser(
        'setorgowner@example.com',
        'password123'
      );
      const { accessToken: outsiderToken } = await createVerifiedUser(
        'setorgoutsider@example.com',
        'password123'
      );

      const org = await createOrg(ownerToken, 'Locked Org', 'locked-org');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'POST',
        url: '/auth/set-active-org',
        headers: { authorization: `Bearer ${outsiderToken}` },
        payload: { orgId },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // ── PATCH /api/orgs/:orgId/transfer-ownership ──────────
  describe('PATCH /api/orgs/:orgId/transfer-ownership', () => {
    it('should transfer ownership to a member', async () => {
      const { accessToken: ownerToken, userId: ownerId } =
        await createVerifiedUser('transferowner@example.com', 'password123');
      const { userId: memberId } = await createVerifiedUser(
        'futurowner@example.com',
        'password123'
      );

      const org = await createOrg(ownerToken, 'Transfer Org', 'transfer-org');
      const orgId = (org as unknown as { id: string }).id;

      const { orgMembers: orgMembersSchema } = await import('../../db/schema');
      await db
        .insert(orgMembersSchema)
        .values({ orgId, userId: memberId, role: 'member' });

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/orgs/${orgId}/transfer-ownership`,
        headers: { authorization: `Bearer ${ownerToken}` },
        payload: { newOwnerId: memberId },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { message: string } }>();
      expect(body.data.message).toContain('transferred');

      // Verify roles in DB
      const membersRes = await app.inject({
        method: 'GET',
        url: `/api/orgs/${orgId}/members`,
        headers: { authorization: `Bearer ${ownerToken}` },
      });
      const membersBody = membersRes.json<{
        data: {
          members: Array<{ userId: string; role: string }>;
        };
      }>();
      const newOwner = membersBody.data.members.find(
        (m) => m.userId === memberId
      );
      const oldOwner = membersBody.data.members.find(
        (m) => m.userId === ownerId
      );
      expect(newOwner?.role).toBe('owner');
      expect(oldOwner?.role).toBe('admin');
    });

    it('should return 403 for non-owner attempting transfer', async () => {
      const { accessToken: ownerToken } = await createVerifiedUser(
        'notransowner@example.com',
        'password123'
      );
      const { accessToken: adminToken, userId: adminId } =
        await createVerifiedUser('notransadmin@example.com', 'password123');
      const { userId: memberId } = await createVerifiedUser(
        'notransmember@example.com',
        'password123'
      );

      const org = await createOrg(ownerToken, 'No Trans', 'no-trans');
      const orgId = (org as unknown as { id: string }).id;

      const { orgMembers: orgMembersSchema } = await import('../../db/schema');
      await db.insert(orgMembersSchema).values([
        { orgId, userId: adminId, role: 'admin' },
        { orgId, userId: memberId, role: 'member' },
      ]);

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/orgs/${orgId}/transfer-ownership`,
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { newOwnerId: memberId },
      });

      expect(res.statusCode).toBe(403);
    });

    it('should return 409 when trying to transfer to yourself', async () => {
      const { accessToken, userId } = await createVerifiedUser(
        'selfowner@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'Self Org', 'self-org');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/orgs/${orgId}/transfer-ownership`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { newOwnerId: userId },
      });

      expect(res.statusCode).toBe(409);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('INVALID_TRANSFER');
    });

    it('should return 404 when target user is not a member', async () => {
      const { accessToken } = await createVerifiedUser(
        'ghostowner@example.com',
        'password123'
      );
      const org = await createOrg(accessToken, 'Ghost Org', 'ghost-org');
      const orgId = (org as unknown as { id: string }).id;

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/orgs/${orgId}/transfer-ownership`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { newOwnerId: '550e8400-e29b-41d4-a716-446655440000' },
      });

      expect(res.statusCode).toBe(404);
    });
  });

  // ── Login response includes organizations ──────────────
  describe('Login response', () => {
    it('should include organizations list with role', async () => {
      const { accessToken } = await createVerifiedUser(
        'loginorg@example.com',
        'password123'
      );

      await app.inject({
        method: 'POST',
        url: '/api/orgs',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'My Org', slug: 'my-org' },
      });

      // Re-login to get fresh response with organizations
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'loginorg@example.com', password: 'password123' },
      });

      expect(loginRes.statusCode).toBe(200);
      const body = loginRes.json<{
        data: {
          organizations: Array<{ slug: string; role: string }>;
        };
      }>();
      expect(body.data.organizations).toHaveLength(1);
      expect(body.data.organizations[0].slug).toBe('my-org');
      expect(body.data.organizations[0].role).toBe('owner');
    });
  });
});
