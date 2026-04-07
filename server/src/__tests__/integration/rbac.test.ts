import { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users, roles } from '../../db/schema';
import { eq, sql } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';
import { tokenService } from '../../services/token.service';
import { TokenUser } from '../../utils/types';

describe('RBAC Routes + Authorize Middleware', () => {
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
  async function createVerifiedUser(email: string, password: string) {
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

    return userId;
  }

  async function loginAndGetToken(email: string, password: string) {
    const res = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password },
    });
    return res.json<{
      data: { accessToken: string; refreshToken: string };
    }>().data.accessToken;
  }

  async function generateAdminToken(userId: string, email: string) {
    const tokenUser: TokenUser = {
      id: userId,
      email,
      roles: ['admin'],
      permissions: [
        'read:profile',
        'write:profile',
        'read:users',
        'write:users',
        'read:roles',
        'write:roles',
        'read:audit-logs',
      ],
      orgId: null,
      orgRole: null,
      orgPermissions: [],
    };
    return tokenService.generateAccessToken(tokenUser);
  }

  // ── GET /api/roles ────────────────────────────────────
  describe('GET /api/roles', () => {
    it('should return all roles for admin user', async () => {
      const userId = await createVerifiedUser(
        'admin@example.com',
        'password123'
      );
      const adminToken = await generateAdminToken(userId, 'admin@example.com');

      const res = await app.inject({
        method: 'GET',
        url: '/api/roles',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        success: boolean;
        data: { roles: Array<{ name: string }> };
      }>();
      expect(body.success).toBe(true);

      const roleNames = body.data.roles.map((r) => r.name);
      expect(roleNames).toContain('user');
      expect(roleNames).toContain('moderator');
      expect(roleNames).toContain('admin');
    });

    it('should reject unauthenticated request', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/roles',
      });

      expect(res.statusCode).toBe(401);
    });

    it('should reject user without read:roles permission', async () => {
      await createVerifiedUser('user@example.com', 'password123');
      const userToken = await loginAndGetToken(
        'user@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/roles',
        headers: { authorization: `Bearer ${userToken}` },
      });

      expect(res.statusCode).toBe(403);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });

  // ── GET /api/users/:userId/roles ──────────────────────
  describe('GET /api/users/:userId/roles', () => {
    it('should return roles and permissions for a user', async () => {
      const userId = await createVerifiedUser(
        'target@example.com',
        'password123'
      );
      const adminToken = await generateAdminToken(userId, 'target@example.com');

      const res = await app.inject({
        method: 'GET',
        url: `/api/users/${userId}/roles`,
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        success: boolean;
        data: { userId: string; roles: string[]; permissions: string[] };
      }>();
      expect(body.data.userId).toBe(userId);
      expect(body.data.roles).toContain('user');
      expect(body.data.permissions).toContain('read:profile');
    });
  });

  // ── POST /api/users/:userId/roles ─────────────────────
  describe('POST /api/users/:userId/roles', () => {
    it('should assign a role to a user', async () => {
      const userId = await createVerifiedUser(
        'promote@example.com',
        'password123'
      );
      const adminToken = await generateAdminToken(
        userId,
        'promote@example.com'
      );

      // Get the moderator role ID
      const [modRole] = await db
        .select()
        .from(roles)
        .where(eq(roles.name, 'moderator'));

      const res = await app.inject({
        method: 'POST',
        url: `/api/users/${userId}/roles`,
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { roleId: modRole.id },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        success: boolean;
        data: { message: string };
      }>();
      expect(body.data.message).toContain('Role assigned');
    });

    it('should return 400 for invalid roleId format', async () => {
      const userId = await createVerifiedUser(
        'badreq@example.com',
        'password123'
      );
      const adminToken = await generateAdminToken(userId, 'badreq@example.com');

      const res = await app.inject({
        method: 'POST',
        url: `/api/users/${userId}/roles`,
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { roleId: 'not-a-uuid' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('should return 404 for non-existent user', async () => {
      const userId = await createVerifiedUser(
        'admin2@example.com',
        'password123'
      );
      const adminToken = await generateAdminToken(userId, 'admin2@example.com');

      const [modRole] = await db
        .select()
        .from(roles)
        .where(eq(roles.name, 'moderator'));

      const res = await app.inject({
        method: 'POST',
        url: '/api/users/550e8400-e29b-41d4-a716-446655440000/roles',
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { roleId: modRole.id },
      });

      expect(res.statusCode).toBe(404);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('USER_NOT_FOUND');
    });

    it('should return 404 for non-existent role', async () => {
      const userId = await createVerifiedUser(
        'admin3@example.com',
        'password123'
      );
      const adminToken = await generateAdminToken(userId, 'admin3@example.com');

      const res = await app.inject({
        method: 'POST',
        url: `/api/users/${userId}/roles`,
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { roleId: '550e8400-e29b-41d4-a716-446655440000' },
      });

      expect(res.statusCode).toBe(404);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('ROLE_NOT_FOUND');
    });

    it('should reject without write:roles permission', async () => {
      await createVerifiedUser('regular@example.com', 'password123');
      const userToken = await loginAndGetToken(
        'regular@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/users/550e8400-e29b-41d4-a716-446655440000/roles',
        headers: { authorization: `Bearer ${userToken}` },
        payload: { roleId: '550e8400-e29b-41d4-a716-446655440000' },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // ── DELETE /api/users/:userId/roles/:roleId ───────────
  describe('DELETE /api/users/:userId/roles/:roleId', () => {
    it('should remove a role from a user', async () => {
      const userId = await createVerifiedUser(
        'demote@example.com',
        'password123'
      );
      const adminToken = await generateAdminToken(userId, 'demote@example.com');

      // Get the user role ID (assigned by default on registration)
      const [userRole] = await db
        .select()
        .from(roles)
        .where(eq(roles.name, 'user'));

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/users/${userId}/roles/${userRole.id}`,
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        success: boolean;
        data: { message: string };
      }>();
      expect(body.data.message).toContain('Role removed');
    });
  });

  // ── GET /api/admin/audit-logs ─────────────────────────
  describe('GET /api/admin/audit-logs', () => {
    it('should return audit logs for admin', async () => {
      // Register creates an audit log entry
      const userId = await createVerifiedUser(
        'auditor@example.com',
        'password123'
      );
      const adminToken = await generateAdminToken(
        userId,
        'auditor@example.com'
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/admin/audit-logs',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        success: boolean;
        data: {
          logs: Array<{ eventType: string }>;
          meta: { page: number; limit: number };
        };
      }>();
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data.logs)).toBe(true);
      expect(body.data.meta.page).toBe(1);
    });

    it('should reject without read:audit-logs permission', async () => {
      await createVerifiedUser('noaudit@example.com', 'password123');
      const userToken = await loginAndGetToken(
        'noaudit@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/admin/audit-logs',
        headers: { authorization: `Bearer ${userToken}` },
      });

      expect(res.statusCode).toBe(403);
    });
  });
});
