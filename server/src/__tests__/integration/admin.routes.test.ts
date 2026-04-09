import { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users } from '../../db/schema';
import { eq, sql } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';

describe('Admin Routes', () => {
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
  async function registerAndLogin(email: string, password: string) {
    await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password },
    });
    await db
      .update(users)
      .set({ isVerified: true })
      .where(eq(users.email, email));

    const loginRes = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password },
    });
    return loginRes.json<{ data: { accessToken: string } }>().data;
  }

  async function makeAdmin(email: string) {
    await db.execute(
      sql`INSERT INTO user_roles (user_id, role_id)
          SELECT u.id, r.id FROM users u, roles r
          WHERE u.email = ${email} AND r.name = 'admin'
          ON CONFLICT DO NOTHING`
    );
  }

  // ── GET /api/admin/users ───────────────────────────────
  describe('GET /api/admin/users', () => {
    it('should return paginated user list for admin', async () => {
      await registerAndLogin('admin@example.com', 'password123');
      await makeAdmin('admin@example.com');

      // Re-login to get token with admin permissions
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'admin@example.com', password: 'password123' },
      });
      const { accessToken: adminToken } = loginRes.json<{
        data: { accessToken: string };
      }>().data;

      const res = await app.inject({
        method: 'GET',
        url: '/api/admin/users',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: unknown[]; meta: { total: number } }>();
      expect(body.meta.total).toBeGreaterThanOrEqual(1);
      expect(JSON.stringify(body)).not.toContain('passwordHash');
    });

    it('should return 403 for non-admin user', async () => {
      const { accessToken } = await registerAndLogin(
        'user@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/admin/users',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(403);
    });

    it('should filter users by email', async () => {
      await registerAndLogin('admin2@example.com', 'password123');
      await makeAdmin('admin2@example.com');
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'admin2@example.com', password: 'password123' },
      });
      const { accessToken: adminToken } = loginRes.json<{
        data: { accessToken: string };
      }>().data;

      const res = await app.inject({
        method: 'GET',
        url: '/api/admin/users?email=admin2',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { email: string }[] }>();
      expect(body.data.every((u) => u.email.includes('admin2'))).toBe(true);
    });
  });

  // ── POST /api/admin/users/:id/disable and enable ───────
  describe('disable / enable user', () => {
    it('should disable a user and block their login', async () => {
      // Setup admin
      await registerAndLogin('admin3@example.com', 'password123');
      await makeAdmin('admin3@example.com');
      const adminLoginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'admin3@example.com', password: 'password123' },
      });
      const { accessToken: adminToken } = adminLoginRes.json<{
        data: { accessToken: string };
      }>().data;

      // Setup target user
      await registerAndLogin('target@example.com', 'password123');
      const [targetUser] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, 'target@example.com'));

      // Disable the user
      const disableRes = await app.inject({
        method: 'POST',
        url: `/api/admin/users/${targetUser.id}/disable`,
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(disableRes.statusCode).toBe(200);

      // Target user can no longer login
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'target@example.com', password: 'password123' },
      });
      expect(loginRes.statusCode).toBe(403);
    });

    it('should re-enable a disabled user', async () => {
      await registerAndLogin('admin4@example.com', 'password123');
      await makeAdmin('admin4@example.com');
      const adminLoginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'admin4@example.com', password: 'password123' },
      });
      const { accessToken: adminToken } = adminLoginRes.json<{
        data: { accessToken: string };
      }>().data;

      await registerAndLogin('target2@example.com', 'password123');
      const [targetUser] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, 'target2@example.com'));

      // Disable then enable
      await app.inject({
        method: 'POST',
        url: `/api/admin/users/${targetUser.id}/disable`,
        headers: { authorization: `Bearer ${adminToken}` },
      });

      const enableRes = await app.inject({
        method: 'POST',
        url: `/api/admin/users/${targetUser.id}/enable`,
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(enableRes.statusCode).toBe(200);

      // User can login again
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'target2@example.com', password: 'password123' },
      });
      expect(loginRes.statusCode).toBe(200);
    });

    it('should return 404 when disabling a non-existent user', async () => {
      await registerAndLogin('admin5@example.com', 'password123');
      await makeAdmin('admin5@example.com');
      const adminLoginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'admin5@example.com', password: 'password123' },
      });
      const { accessToken: adminToken } = adminLoginRes.json<{
        data: { accessToken: string };
      }>().data;

      const res = await app.inject({
        method: 'POST',
        url: '/api/admin/users/00000000-0000-0000-0000-000000000000/disable',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  // ── GET /api/admin/users/:id/sessions ──────────────────
  describe('GET /api/admin/users/:id/sessions', () => {
    it('should return sessions for a specific user', async () => {
      await registerAndLogin('admin6@example.com', 'password123');
      await makeAdmin('admin6@example.com');
      const adminLoginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'admin6@example.com', password: 'password123' },
      });
      const { accessToken: adminToken } = adminLoginRes.json<{
        data: { accessToken: string };
      }>().data;

      await registerAndLogin('viewme@example.com', 'password123');
      const [targetUser] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, 'viewme@example.com'));

      const res = await app.inject({
        method: 'GET',
        url: `/api/admin/users/${targetUser.id}/sessions`,
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { sessions: unknown[] } }>();
      expect(body.data.sessions).toHaveLength(1);
      expect(JSON.stringify(body)).not.toContain('tokenHash');
    });
  });
});
