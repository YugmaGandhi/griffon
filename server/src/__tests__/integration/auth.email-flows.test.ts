import { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users, emailTokens } from '../../db/schema';
import { eq, sql, and, isNull } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';
import crypto from 'crypto';

describe('Email Flows — verify-email + forgot/reset-password', () => {
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
  async function registerUser(email: string, password: string) {
    return app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password },
    });
  }

  /**
   * Retrieves the raw token for a given user + type.
   * Since the DB stores a SHA-256 hash, we can't reverse it.
   * Instead, we insert a known token directly for testing.
   */
  async function createTestEmailToken(
    userId: string,
    type: 'email_verification' | 'password_reset',
    expiryHours: number
  ): Promise<string> {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + expiryHours);

    // Invalidate existing tokens of this type
    await db
      .update(emailTokens)
      .set({ usedAt: new Date() })
      .where(
        and(
          eq(emailTokens.userId, userId),
          eq(emailTokens.type, type),
          isNull(emailTokens.usedAt)
        )
      );

    await db.insert(emailTokens).values({
      userId,
      tokenHash,
      type,
      expiresAt,
    });

    return rawToken;
  }

  // ── Verify Email ───────────────────────────────────────
  describe('GET /auth/verify-email', () => {
    it('should verify email with valid token', async () => {
      const registerRes = await registerUser(
        'verify@example.com',
        'password123'
      );
      const userId = registerRes.json<{
        data: { user: { id: string } };
      }>().data.user.id;

      const token = await createTestEmailToken(
        userId,
        'email_verification',
        24
      );

      const res = await app.inject({
        method: 'GET',
        url: `/auth/verify-email?token=${token}`,
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        success: boolean;
        data: { message: string };
      }>();
      expect(body.data.message).toContain('Email verified');

      // User should now be verified in DB
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.email, 'verify@example.com'));
      expect(user.isVerified).toBe(true);
    });

    it('should allow login after email verification', async () => {
      const registerRes = await registerUser('flow@example.com', 'password123');
      const userId = registerRes.json<{
        data: { user: { id: string } };
      }>().data.user.id;

      // Verify email
      const token = await createTestEmailToken(
        userId,
        'email_verification',
        24
      );
      await app.inject({
        method: 'GET',
        url: `/auth/verify-email?token=${token}`,
      });

      // Should now be able to login
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'flow@example.com', password: 'password123' },
      });

      expect(loginRes.statusCode).toBe(200);
    });

    it('should reject invalid token', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/auth/verify-email?token=invalid-token-here',
      });

      expect(res.statusCode).toBe(400);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('TOKEN_INVALID');
    });

    it('should reject already-used token', async () => {
      const registerRes = await registerUser('used@example.com', 'password123');
      const userId = registerRes.json<{
        data: { user: { id: string } };
      }>().data.user.id;

      const token = await createTestEmailToken(
        userId,
        'email_verification',
        24
      );

      // Use the token once
      await app.inject({
        method: 'GET',
        url: `/auth/verify-email?token=${token}`,
      });

      // Try to use it again
      const res = await app.inject({
        method: 'GET',
        url: `/auth/verify-email?token=${token}`,
      });

      expect(res.statusCode).toBe(400);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('TOKEN_INVALID');
    });

    it('should return 400 when token query param is missing', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/auth/verify-email',
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // ── Forgot Password ────────────────────────────────────
  describe('POST /auth/forgot-password', () => {
    it('should return 200 for existing email (never reveal existence)', async () => {
      await registerUser('forgot@example.com', 'password123');

      const res = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        payload: { email: 'forgot@example.com' },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        success: boolean;
        data: { message: string };
      }>();
      expect(body.data.message).toContain('If that email is registered');
    });

    it('should return 200 for non-existent email (prevents enumeration)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        payload: { email: 'nobody@example.com' },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        success: boolean;
        data: { message: string };
      }>();
      expect(body.data.message).toContain('If that email is registered');
    });

    it('should return 400 for invalid email format', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        payload: { email: 'not-an-email' },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // ── Reset Password ─────────────────────────────────────
  describe('POST /auth/reset-password', () => {
    it('should reset password with valid token', async () => {
      const registerRes = await registerUser(
        'reset@example.com',
        'oldpassword123'
      );
      const userId = registerRes.json<{
        data: { user: { id: string } };
      }>().data.user.id;

      // Verify email first (needed for login later)
      await db
        .update(users)
        .set({ isVerified: true })
        .where(eq(users.email, 'reset@example.com'));

      const token = await createTestEmailToken(userId, 'password_reset', 1);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        payload: { token, newPassword: 'newpassword456' },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        success: boolean;
        data: { message: string };
      }>();
      expect(body.data.message).toContain('Password reset successfully');
    });

    it('should allow login with new password after reset', async () => {
      const registerRes = await registerUser(
        'resetlogin@example.com',
        'oldpass123'
      );
      const userId = registerRes.json<{
        data: { user: { id: string } };
      }>().data.user.id;

      await db
        .update(users)
        .set({ isVerified: true })
        .where(eq(users.email, 'resetlogin@example.com'));

      const token = await createTestEmailToken(userId, 'password_reset', 1);

      await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        payload: { token, newPassword: 'brandnewpass789' },
      });

      // Old password should fail
      const oldPassRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'resetlogin@example.com', password: 'oldpass123' },
      });
      expect(oldPassRes.statusCode).toBe(401);

      // New password should work
      const newPassRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'resetlogin@example.com',
          password: 'brandnewpass789',
        },
      });
      expect(newPassRes.statusCode).toBe(200);
    });

    it('should revoke all sessions after password reset', async () => {
      const registerRes = await registerUser(
        'revoke@example.com',
        'password123'
      );
      const userId = registerRes.json<{
        data: { user: { id: string } };
      }>().data.user.id;

      await db
        .update(users)
        .set({ isVerified: true })
        .where(eq(users.email, 'revoke@example.com'));

      // Login to get a refresh token
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'revoke@example.com', password: 'password123' },
      });
      const { refreshToken } = loginRes.json<{
        data: { refreshToken: string };
      }>().data;

      // Reset password
      const resetToken = await createTestEmailToken(
        userId,
        'password_reset',
        1
      );
      await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        payload: { token: resetToken, newPassword: 'newpassword456' },
      });

      // Old refresh token should now be revoked
      const refreshRes = await app.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: { refreshToken },
      });
      expect(refreshRes.statusCode).toBe(401);
    });

    it('should reject invalid reset token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        payload: { token: 'invalid-token', newPassword: 'newpassword456' },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json<{ error: { code: string } }>();
      expect(body.error.code).toBe('TOKEN_INVALID');
    });

    it('should reject short password', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        payload: { token: 'some-token', newPassword: 'short' },
      });

      expect(res.statusCode).toBe(400);
    });
  });
});
