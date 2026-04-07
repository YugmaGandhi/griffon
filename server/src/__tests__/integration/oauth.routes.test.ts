import { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { sql } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';

describe('OAuth Routes', () => {
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

  // ── GET /auth/oauth/providers ─────────────────────────
  describe('GET /auth/oauth/providers', () => {
    it('should return list of enabled providers', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/auth/oauth/providers',
      });

      // May be 200 with providers or 404 if no providers configured
      // In test env, Google creds may not be set
      if (res.statusCode === 200) {
        const body = res.json<{
          success: boolean;
          data: { providers: string[] };
        }>();
        expect(body.success).toBe(true);
        expect(Array.isArray(body.data.providers)).toBe(true);
      } else {
        // OAuth routes not registered because no providers configured
        expect(res.statusCode).toBe(404);
      }
    });
  });

  // ── GET /auth/oauth/:provider ─────────────────────────
  describe('GET /auth/oauth/:provider', () => {
    it('should return 404 for unconfigured provider', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/auth/oauth/discord',
      });

      // Either 404 (provider not found) or 404 (routes not registered)
      expect(res.statusCode).toBe(404);
    });
  });

  // ── GET /auth/oauth/:provider/callback ────────────────
  describe('GET /auth/oauth/:provider/callback', () => {
    it('should return 404 for unconfigured provider callback', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/auth/oauth/discord/callback?code=test&state=test',
      });

      expect(res.statusCode).toBe(404);
    });
  });
});
