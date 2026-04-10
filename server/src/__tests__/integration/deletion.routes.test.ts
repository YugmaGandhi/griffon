import { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users } from '../../db/schema';
import { eq, sql } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';

describe('Deletion Routes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    await redis.connect();
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    await redis.flushdb();
    await db.execute(
      sql`TRUNCATE TABLE deletion_requests, audit_logs, refresh_tokens, email_tokens, user_roles, role_permissions, roles, permissions, org_role_permissions, org_member_roles, org_permissions, org_roles, org_invitations, org_members, organizations, users RESTART IDENTITY CASCADE`
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

  // ── POST /auth/account/delete ──────────────────────────
  describe('POST /auth/account/delete', () => {
    it('should create a deletion request and return scheduledPurgeAt', async () => {
      const { accessToken } = await registerAndLogin(
        'user@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'POST',
        url: '/auth/account/delete',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { scheduledPurgeAt: string } }>();
      expect(body.data.scheduledPurgeAt).toBeDefined();
    });

    it('should return 409 if a deletion request already exists', async () => {
      const { accessToken } = await registerAndLogin(
        'user2@example.com',
        'password123'
      );

      await app.inject({
        method: 'POST',
        url: '/auth/account/delete',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/account/delete',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(409);
    });

    it('should return 401 without auth token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/account/delete',
      });
      expect(res.statusCode).toBe(401);
    });
  });

  // ── DELETE /auth/account/delete ────────────────────────
  describe('DELETE /auth/account/delete', () => {
    it('should cancel a pending deletion request', async () => {
      const { accessToken } = await registerAndLogin(
        'user3@example.com',
        'password123'
      );

      await app.inject({
        method: 'POST',
        url: '/auth/account/delete',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      const res = await app.inject({
        method: 'DELETE',
        url: '/auth/account/delete',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('should return 404 if no pending request exists', async () => {
      const { accessToken } = await registerAndLogin(
        'user4@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'DELETE',
        url: '/auth/account/delete',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(404);
    });
  });

  // ── POST /api/admin/users/:id/delete ───────────────────
  describe('POST /api/admin/users/:id/delete', () => {
    it('should permanently delete a user', async () => {
      await registerAndLogin('admin@example.com', 'password123');
      await makeAdmin('admin@example.com');
      const adminLoginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'admin@example.com', password: 'password123' },
      });
      const { accessToken: adminToken } = adminLoginRes.json<{
        data: { accessToken: string };
      }>().data;

      await registerAndLogin('victim@example.com', 'password123');
      const [targetUser] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, 'victim@example.com'));

      const res = await app.inject({
        method: 'POST',
        url: `/api/admin/users/${targetUser.id}/delete`,
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(200);

      // Confirm user is gone
      const [deletedUser] = await db
        .select()
        .from(users)
        .where(eq(users.id, targetUser.id));
      expect(deletedUser).toBeUndefined();
    });

    it('should return 403 when admin tries to delete themselves', async () => {
      await registerAndLogin('admin2@example.com', 'password123');
      await makeAdmin('admin2@example.com');
      const adminLoginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'admin2@example.com', password: 'password123' },
      });
      const { accessToken: adminToken } = adminLoginRes.json<{
        data: { accessToken: string };
      }>().data;

      const [adminUser] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, 'admin2@example.com'));

      const res = await app.inject({
        method: 'POST',
        url: `/api/admin/users/${adminUser.id}/delete`,
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(403);
    });

    it('should return 404 for non-existent user', async () => {
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

      const res = await app.inject({
        method: 'POST',
        url: '/api/admin/users/00000000-0000-0000-0000-000000000000/delete',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(404);
    });

    it('should return 403 for non-admin user', async () => {
      const { accessToken } = await registerAndLogin(
        'regular@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/admin/users/00000000-0000-0000-0000-000000000000/delete',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(403);
    });
  });
});
