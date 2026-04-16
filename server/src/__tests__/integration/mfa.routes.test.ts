import { FastifyInstance } from 'fastify';
import { TOTP, Secret } from 'otpauth';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users } from '../../db/schema';
import { eq, sql } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';

// ── Helpers ────────────────────────────────────────────────

function generateTotpCode(base32Secret: string): string {
  const totp = new TOTP({
    issuer: 'Griffon',
    label: 'test',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(base32Secret),
  });
  return totp.generate();
}

describe('MFA Routes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    await redis.connect();
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    await redis.flushdb();
    // CASCADE truncates mfa_settings, mfa_recovery_codes, org_mfa_policies
    // automatically because they FK-reference users/organizations which are listed
    await db.execute(
      sql`TRUNCATE TABLE webhook_deliveries, webhook_endpoints, deletion_requests, audit_logs, refresh_tokens, email_tokens, user_roles, role_permissions, roles, permissions, org_role_permissions, org_member_roles, org_permissions, org_roles, org_invitations, org_members, organizations, users RESTART IDENTITY CASCADE`
    );
    await seedSystemData();
  });

  afterAll(async () => {
    await app.close();
  });

  // ── Shared setup helpers ──────────────────────────────────

  async function registerAndLogin(email: string, password = 'Password1!') {
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
    return loginRes.json<{
      data: {
        mfaRequired: boolean;
        accessToken?: string;
        refreshToken?: string;
        mfaToken?: string;
      };
    }>().data;
  }

  // Sets up AND confirms MFA enrollment; returns the accessToken used
  async function enrollMfa(accessToken: string) {
    const setupRes = await app.inject({
      method: 'POST',
      url: '/auth/mfa/setup',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    const { secret } = setupRes.json<{
      data: { secret: string; otpauthUri: string; recoveryCodes: string[] };
    }>().data;

    const code = generateTotpCode(secret);
    await app.inject({
      method: 'POST',
      url: '/auth/mfa/verify-setup',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { code },
    });

    return { secret };
  }

  // ── POST /auth/mfa/setup ──────────────────────────────────
  describe('POST /auth/mfa/setup', () => {
    it('should return 401 without authentication', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
      });
      expect(res.statusCode).toBe(401);
    });

    it('should return 201 with otpauthUri, secret, and 8 recovery codes', async () => {
      const { accessToken } = await registerAndLogin('setup@test.com');

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json<{
        data: { otpauthUri: string; secret: string; recoveryCodes: string[] };
      }>();
      expect(body.data.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
      expect(typeof body.data.secret).toBe('string');
      expect(body.data.recoveryCodes).toHaveLength(8);
      body.data.recoveryCodes.forEach((code) => {
        expect(code).toMatch(/^[0-9A-F]{10}-[0-9A-F]{10}$/);
      });
    });
  });

  // ── POST /auth/mfa/verify-setup ───────────────────────────
  describe('POST /auth/mfa/verify-setup', () => {
    it('should return 400 for an invalid code format', async () => {
      const { accessToken } = await registerAndLogin('vs-invalid@test.com');
      await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { code: 'abc' }, // not 6 digits
      });

      expect(res.statusCode).toBe(400);
    });

    it('should return 400 MFA_INVALID_CODE for a wrong 6-digit code', async () => {
      const { accessToken } = await registerAndLogin('vs-wrong@test.com');
      await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { code: '000000' },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json<{ error: { code: string } }>().error.code).toBe(
        'MFA_INVALID_CODE'
      );
    });

    it('should return 200 and enable MFA for a valid TOTP code', async () => {
      const { accessToken } = await registerAndLogin('vs-valid@test.com');

      const setupRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      const { secret } = setupRes.json<{ data: { secret: string } }>().data;

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { code: generateTotpCode(secret) },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { mfa: { isEnabled: boolean } } }>();
      expect(body.data.mfa.isEnabled).toBe(true);
      // encryptedSecret must never leak to the client
      expect(
        (body.data.mfa as Record<string, unknown>).encryptedSecret
      ).toBeUndefined();
    });
  });

  // ── GET /auth/mfa/status ──────────────────────────────────
  describe('GET /auth/mfa/status', () => {
    it('should return enabled=false before enrollment', async () => {
      const { accessToken } = await registerAndLogin('status-off@test.com');

      const res = await app.inject({
        method: 'GET',
        url: '/auth/mfa/status',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      expect(
        res.json<{ data: { mfa: { enabled: boolean } } }>().data.mfa.enabled
      ).toBe(false);
    });

    it('should return enabled=true with 8 recovery codes after enrollment', async () => {
      const { accessToken } = await registerAndLogin('status-on@test.com');
      await enrollMfa(accessToken!);

      const res = await app.inject({
        method: 'GET',
        url: '/auth/mfa/status',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const { mfa } = res.json<{
        data: { mfa: { enabled: boolean; recoveryCodesRemaining: number } };
      }>().data;
      expect(mfa.enabled).toBe(true);
      expect(mfa.recoveryCodesRemaining).toBe(8);
    });
  });

  // ── Two-step login flow ───────────────────────────────────
  describe('POST /auth/mfa/verify (two-step login)', () => {
    it('should return mfaRequired:true on login when MFA is enrolled', async () => {
      const email = 'mfa-login@test.com';
      const password = 'Password1!';
      const firstLogin = await registerAndLogin(email, password);
      await enrollMfa(firstLogin.accessToken!);

      // Second login — should require MFA
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password },
      });

      expect(loginRes.statusCode).toBe(200);
      const body = loginRes.json<{
        data: { mfaRequired: boolean; mfaToken: string };
      }>();
      expect(body.data.mfaRequired).toBe(true);
      expect(typeof body.data.mfaToken).toBe('string');
    });

    it('should return full tokens on valid TOTP code at step 2', async () => {
      const email = 'mfa-step2@test.com';
      const password = 'Password1!';
      const firstLogin = await registerAndLogin(email, password);
      const { secret } = await enrollMfa(firstLogin.accessToken!);

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password },
      });
      const { mfaToken } = loginRes.json<{
        data: { mfaToken: string };
      }>().data;

      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        payload: { mfaToken, code: generateTotpCode(secret) },
      });

      expect(verifyRes.statusCode).toBe(200);
      const tokens = verifyRes.json<{
        data: {
          accessToken: string;
          refreshToken: string;
          mfaRequired: boolean;
        };
      }>().data;
      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();
      expect(tokens.mfaRequired).toBe(false);
    });

    it('should return 401 for an invalid or expired mfaToken', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        payload: { mfaToken: 'invalid-token', code: '123456' },
      });

      expect(res.statusCode).toBe(401);
    });

    it('should return 400 MFA_INVALID_CODE for wrong TOTP at step 2', async () => {
      const email = 'mfa-wrong@test.com';
      const password = 'Password1!';
      const firstLogin = await registerAndLogin(email, password);
      await enrollMfa(firstLogin.accessToken!);

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password },
      });
      const { mfaToken } = loginRes.json<{ data: { mfaToken: string } }>().data;

      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        payload: { mfaToken, code: '000000' },
      });

      expect(verifyRes.statusCode).toBe(400);
      expect(verifyRes.json<{ error: { code: string } }>().error.code).toBe(
        'MFA_INVALID_CODE'
      );
    });

    it('should reject the mfaToken a second time (single-use)', async () => {
      const email = 'mfa-reuse@test.com';
      const password = 'Password1!';
      const firstLogin = await registerAndLogin(email, password);
      const { secret } = await enrollMfa(firstLogin.accessToken!);

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password },
      });
      const { mfaToken } = loginRes.json<{ data: { mfaToken: string } }>().data;

      // Capture once so both requests use the same code — avoids flakiness
      // if the 30-second TOTP window rolls over between the two inject calls.
      const code = generateTotpCode(secret);

      // Use it once successfully
      await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        payload: { mfaToken, code },
      });

      // Second use must fail — mfaToken is single-use (consumed above)
      const reuse = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        payload: { mfaToken, code },
      });

      expect(reuse.statusCode).toBe(401);
    });
  });

  // ── Recovery code login ───────────────────────────────────
  describe('Recovery code login flow', () => {
    it('should accept a recovery code at MFA step 2 and mark it as used', async () => {
      const email = 'recovery@test.com';
      const password = 'Password1!';
      const firstLogin = await registerAndLogin(email, password);

      // Setup MFA and capture recovery codes
      const setupRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { authorization: `Bearer ${firstLogin.accessToken}` },
      });
      const { secret, recoveryCodes } = setupRes.json<{
        data: { secret: string; recoveryCodes: string[] };
      }>().data;
      await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { authorization: `Bearer ${firstLogin.accessToken}` },
        payload: { code: generateTotpCode(secret) },
      });

      // Login — get mfaToken
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password },
      });
      const { mfaToken } = loginRes.json<{ data: { mfaToken: string } }>().data;

      // Use a recovery code instead of TOTP
      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        payload: { mfaToken, code: recoveryCodes[0] },
      });

      expect(verifyRes.statusCode).toBe(200);

      // Recovery code is single-use — status should show one fewer code
      const statusRes = await app.inject({
        method: 'GET',
        url: '/auth/mfa/status',
        headers: {
          authorization: `Bearer ${verifyRes.json<{ data: { accessToken: string } }>().data.accessToken}`,
        },
      });
      const { mfa } = statusRes.json<{
        data: { mfa: { recoveryCodesRemaining: number } };
      }>().data;
      expect(mfa.recoveryCodesRemaining).toBe(7);
    });
  });

  // ── DELETE /auth/mfa ──────────────────────────────────────
  describe('DELETE /auth/mfa', () => {
    it('should disable MFA with a valid TOTP code', async () => {
      const email = 'disable@test.com';
      const { accessToken } = await registerAndLogin(email);
      const { secret } = await enrollMfa(accessToken!);

      const res = await app.inject({
        method: 'DELETE',
        url: '/auth/mfa',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { code: generateTotpCode(secret) },
      });

      expect(res.statusCode).toBe(200);

      // Status should now show disabled
      const statusRes = await app.inject({
        method: 'GET',
        url: '/auth/mfa/status',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(
        statusRes.json<{ data: { mfa: { enabled: boolean } } }>().data.mfa
          .enabled
      ).toBe(false);
    });

    it('should return 400 MFA_INVALID_CODE for wrong TOTP', async () => {
      const { accessToken } = await registerAndLogin('disable-wrong@test.com');
      await enrollMfa(accessToken!);

      const res = await app.inject({
        method: 'DELETE',
        url: '/auth/mfa',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { code: '000000' },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json<{ error: { code: string } }>().error.code).toBe(
        'MFA_INVALID_CODE'
      );
    });
  });

  // ── POST /auth/mfa/recovery-codes ────────────────────────
  describe('POST /auth/mfa/recovery-codes', () => {
    it('should regenerate 8 fresh recovery codes with a valid TOTP', async () => {
      const { accessToken } = await registerAndLogin('regen@test.com');
      const { secret } = await enrollMfa(accessToken!);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recovery-codes',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { code: generateTotpCode(secret) },
      });

      expect(res.statusCode).toBe(200);
      const { recoveryCodes } = res.json<{
        data: { recoveryCodes: string[] };
      }>().data;
      expect(recoveryCodes).toHaveLength(8);
      recoveryCodes.forEach((code) => {
        expect(code).toMatch(/^[0-9A-F]{10}-[0-9A-F]{10}$/);
      });
    });
  });
});
