import { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users } from '../../db/schema';
import { eq, sql } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';

describe('Auth Cycle — register → login → refresh → logout', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    await redis.connect();
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    // Clear rate limit counters between tests
    await redis.flushdb();
    // TRUNCATE CASCADE handles all FK dependencies atomically
    // Much safer than manual delete ordering
    await db.execute(
      sql`TRUNCATE TABLE audit_logs, refresh_tokens, email_tokens, user_roles, role_permissions, roles, permissions, org_role_permissions, org_member_roles, org_permissions, org_roles, org_invitations, org_members, organizations, users RESTART IDENTITY CASCADE`
    );

    // Re-seed system data after truncate
    await seedSystemData();
  });

  afterAll(async () => {
    await app.close();
  });

  // ── Helper functions ───────────────────────────────────
  async function registerUser(email: string, password: string) {
    return app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password },
    });
  }

  async function verifyUser(email: string) {
    await db
      .update(users)
      .set({ isVerified: true })
      .where(eq(users.email, email));
  }

  async function loginUser(email: string, password: string) {
    return app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password },
    });
  }

  // ── Full cycle test ────────────────────────────────────
  it('should complete full auth cycle successfully', async () => {
    const email = 'cycle@example.com';
    const password = 'password123';

    // Step 1 — Register
    const registerRes = await registerUser(email, password);
    expect(registerRes.statusCode).toBe(201);

    // Step 2 — Verify email
    await verifyUser(email);

    // Step 3 — Login
    const loginRes = await loginUser(email, password);
    expect(loginRes.statusCode).toBe(200);

    const loginBody = loginRes.json<{
      success: boolean;
      data: {
        accessToken: string;
        refreshToken: string;
        expiresIn: number;
        user: { id: string; email: string };
      };
    }>();

    expect(loginBody.success).toBe(true);
    expect(loginBody.data.accessToken).toBeDefined();
    expect(loginBody.data.refreshToken).toBeDefined();
    expect(loginBody.data.expiresIn).toBe(900);

    const { accessToken, refreshToken } = loginBody.data;

    // Step 4 — Get current user
    const meRes = await app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: { authorization: `Bearer ${accessToken}` },
    });

    expect(meRes.statusCode).toBe(200);
    const meBody = meRes.json<{
      success: boolean;
      data: { user: { email: string } };
    }>();
    expect(meBody.data.user.email).toBe(email);

    // Step 5 — Refresh tokens
    const refreshRes = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken },
    });

    expect(refreshRes.statusCode).toBe(200);
    const refreshBody = refreshRes.json<{
      success: boolean;
      data: { accessToken: string; refreshToken: string };
    }>();

    // New tokens must be present and valid strings
    expect(refreshBody.data.accessToken).toBeDefined();
    expect(refreshBody.data.refreshToken).toBeDefined();
    expect(typeof refreshBody.data.accessToken).toBe('string');
    expect(typeof refreshBody.data.refreshToken).toBe('string');

    // New refresh token must be different from old one
    // (access token may be same if generated within same second)
    expect(refreshBody.data.refreshToken).not.toBe(refreshToken);

    const newAccessToken = refreshBody.data.accessToken;
    const newRefreshToken = refreshBody.data.refreshToken;

    // Step 6 — Old refresh token must be rejected
    const oldTokenRes = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken },
    });

    expect(oldTokenRes.statusCode).toBe(401);
    const oldTokenBody = oldTokenRes.json<{
      success: boolean;
      error: { code: string };
    }>();
    expect(oldTokenBody.error.code).toBe('TOKEN_REVOKED');

    // Step 7 — Logout with new token
    const logoutRes = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: { authorization: `Bearer ${newAccessToken}` },
      payload: { refreshToken: newRefreshToken },
    });

    expect(logoutRes.statusCode).toBe(200);

    // Step 8 — Refresh after logout must fail
    const afterLogoutRes = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      payload: { refreshToken: newRefreshToken },
    });

    expect(afterLogoutRes.statusCode).toBe(401);
  });

  // ── Security tests ─────────────────────────────────────
  it('should reject login with wrong password', async () => {
    await registerUser('security@example.com', 'correctpassword');
    await verifyUser('security@example.com');

    const res = await loginUser('security@example.com', 'wrongpassword');
    expect(res.statusCode).toBe(401);

    const body = res.json<{
      error: { code: string };
    }>();
    expect(body.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('should lock account after 5 failed attempts', async () => {
    await registerUser('lockme@example.com', 'correctpassword');
    await verifyUser('lockme@example.com');

    // 5 failed attempts
    for (let i = 0; i < 5; i++) {
      await loginUser('lockme@example.com', 'wrongpassword');
    }

    // 6th attempt should return locked
    const res = await loginUser('lockme@example.com', 'correctpassword');
    expect(res.statusCode).toBe(423);

    const body = res.json<{ error: { code: string } }>();
    expect(body.error.code).toBe('ACCOUNT_LOCKED');
  });

  it('should reject login for unverified email', async () => {
    await registerUser('unverified@example.com', 'password123');
    // Note: NOT calling verifyUser

    const res = await loginUser('unverified@example.com', 'password123');
    expect(res.statusCode).toBe(403);

    const body = res.json<{ error: { code: string } }>();
    expect(body.error.code).toBe('EMAIL_NOT_VERIFIED');
  });

  it('should reject requests with invalid JWT', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: { authorization: 'Bearer invalidtoken' },
    });

    expect(res.statusCode).toBe(401);
  });

  it('should reject requests with no JWT', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/me',
    });

    expect(res.statusCode).toBe(401);
    const body = res.json<{ error: { code: string } }>();
    expect(body.error.code).toBe('MISSING_TOKEN');
  });
});
