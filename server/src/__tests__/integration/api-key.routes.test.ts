import { FastifyInstance } from 'fastify';
import { TOTP, Secret } from 'otpauth';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users, apiKeys } from '../../db/schema';
import { eq, sql } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';
import { env } from '../../config/env';
import crypto from 'crypto';

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

describe('API Key Routes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    await redis.connect();
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    await redis.flushdb();
    await db.execute(
      sql`TRUNCATE TABLE webhook_deliveries, webhook_endpoints, deletion_requests, audit_logs, refresh_tokens, email_tokens, user_roles, role_permissions, roles, permissions, org_role_permissions, org_member_roles, org_permissions, org_roles, org_invitations, org_members, organizations, users RESTART IDENTITY CASCADE`
    );
    await seedSystemData();
  });

  afterAll(async () => {
    await app.close();
  });

  // ── Shared helpers ─────────────────────────────────────────

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
    return loginRes.json<{ data: { accessToken: string } }>().data;
  }

  async function createApiKey(
    token: string,
    overrides: {
      name?: string;
      permissions?: string[];
      expiresAt?: string;
      orgId?: string;
    } = {}
  ) {
    return app.inject({
      method: 'POST',
      url: '/api/api-keys',
      headers: { authorization: `Bearer ${token}` },
      payload: {
        name: overrides.name ?? 'Test Key',
        permissions: overrides.permissions ?? ['read:profile'],
        ...(overrides.expiresAt && { expiresAt: overrides.expiresAt }),
        ...(overrides.orgId && { orgId: overrides.orgId }),
      },
    });
  }

  async function enrollMfa(accessToken: string) {
    const setupRes = await app.inject({
      method: 'POST',
      url: '/auth/mfa/setup',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    const { secret } = setupRes.json<{ data: { secret: string } }>().data;
    await app.inject({
      method: 'POST',
      url: '/auth/mfa/verify-setup',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { code: generateTotpCode(secret) },
    });
    return { secret };
  }

  async function createOrg(token: string, name: string, slug: string) {
    const res = await app.inject({
      method: 'POST',
      url: '/api/orgs',
      headers: { authorization: `Bearer ${token}` },
      payload: { name, slug },
    });
    return res.json<{ data: { organization: { id: string } } }>().data
      .organization;
  }

  // ── POST /api/api-keys — Create ────────────────────────────

  describe('POST /api/api-keys', () => {
    it('should return 401 without authentication', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/api-keys',
        payload: { name: 'My Key', permissions: ['read:profile'] },
      });
      expect(res.statusCode).toBe(401);
    });

    it('should return 201 with plaintext key and safe metadata', async () => {
      const { accessToken } = await registerAndLogin('create@test.com');
      const res = await createApiKey(accessToken);

      expect(res.statusCode).toBe(201);
      const { key, plaintext } = res.json<{
        data: { key: Record<string, unknown>; plaintext: string };
      }>().data;

      // Plaintext has correct format
      expect(plaintext).toMatch(/^grf_live_[A-Za-z0-9_-]{43}$/);

      // Prefix is first 10 chars of the key
      expect(key.prefix).toBe(plaintext.slice(0, 10));

      // keyHash must NEVER appear in the response
      expect(key.keyHash).toBeUndefined();

      // Safe fields are present
      expect(typeof key.id).toBe('string');
      expect(key.name).toBe('Test Key');
      expect(key.revokedAt).toBeNull();
    });

    it('should return 400 for empty permissions', async () => {
      const { accessToken } = await registerAndLogin('no-perms@test.com');
      const res = await app.inject({
        method: 'POST',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'My Key', permissions: [] },
      });
      expect(res.statusCode).toBe(400);
    });

    it('should return 400 when name is missing', async () => {
      const { accessToken } = await registerAndLogin('no-name@test.com');
      const res = await app.inject({
        method: 'POST',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { permissions: ['read:profile'] },
      });
      expect(res.statusCode).toBe(400);
    });

    it('should require totpCode when user has MFA enabled', async () => {
      const { accessToken } = await registerAndLogin('mfa-gate@test.com');
      await enrollMfa(accessToken);

      // No totpCode → MFA_REQUIRED
      const res = await createApiKey(accessToken);
      expect(res.statusCode).toBe(403);
      expect(res.json<{ error: { code: string } }>().error.code).toBe(
        'MFA_REQUIRED'
      );
    });

    it('should create key when valid totpCode is provided with MFA enabled', async () => {
      const { accessToken } = await registerAndLogin('mfa-create@test.com');
      const { secret } = await enrollMfa(accessToken);

      const res = await app.inject({
        method: 'POST',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {
          name: 'CI Key',
          permissions: ['read:profile'],
          totpCode: generateTotpCode(secret),
        },
      });

      expect(res.statusCode).toBe(201);
    });
  });

  // ── GET /api/api-keys — List ───────────────────────────────

  describe('GET /api/api-keys', () => {
    it('should return 401 without authentication', async () => {
      const res = await app.inject({ method: 'GET', url: '/api/api-keys' });
      expect(res.statusCode).toBe(401);
    });

    it('should return empty array when no keys exist', async () => {
      const { accessToken } = await registerAndLogin('list-empty@test.com');
      const res = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json<{ data: { keys: unknown[] } }>().data.keys).toHaveLength(
        0
      );
    });

    it('should return created keys', async () => {
      const { accessToken } = await registerAndLogin('list@test.com');
      await createApiKey(accessToken, { name: 'Key A' });
      await createApiKey(accessToken, { name: 'Key B' });

      const res = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json<{ data: { keys: unknown[] } }>().data.keys).toHaveLength(
        2
      );
    });

    it("should not return another user's keys", async () => {
      const { accessToken: tokenA } = await registerAndLogin('list-a@test.com');
      const { accessToken: tokenB } = await registerAndLogin('list-b@test.com');

      await createApiKey(tokenA, { name: 'User A Key' });

      const res = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${tokenB}` },
      });

      expect(res.json<{ data: { keys: unknown[] } }>().data.keys).toHaveLength(
        0
      );
    });
  });

  // ── GET /api/api-keys/:id — Get single ────────────────────

  describe('GET /api/api-keys/:id', () => {
    it('should return the key for its owner', async () => {
      const { accessToken } = await registerAndLogin('get@test.com');
      const createRes = await createApiKey(accessToken);
      const { key } = createRes.json<{ data: { key: { id: string } } }>().data;

      const res = await app.inject({
        method: 'GET',
        url: `/api/api-keys/${key.id}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json<{ data: { key: { id: string } } }>().data.key.id).toBe(
        key.id
      );
    });

    it("should return 403 for another user's key", async () => {
      const { accessToken: tokenA } = await registerAndLogin('get-a@test.com');
      const { accessToken: tokenB } = await registerAndLogin('get-b@test.com');

      const createRes = await createApiKey(tokenA);
      const { key } = createRes.json<{ data: { key: { id: string } } }>().data;

      const res = await app.inject({
        method: 'GET',
        url: `/api/api-keys/${key.id}`,
        headers: { authorization: `Bearer ${tokenB}` },
      });

      expect(res.statusCode).toBe(403);
    });

    it('should return 404 for a non-existent key', async () => {
      const { accessToken } = await registerAndLogin('get-404@test.com');
      const res = await app.inject({
        method: 'GET',
        url: `/api/api-keys/${crypto.randomUUID()}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  // ── DELETE /api/api-keys/:id — Revoke ─────────────────────

  describe('DELETE /api/api-keys/:id', () => {
    it('should revoke a key and remove it from the list', async () => {
      const { accessToken } = await registerAndLogin('revoke@test.com');
      const createRes = await createApiKey(accessToken);
      const { key } = createRes.json<{ data: { key: { id: string } } }>().data;

      const revokeRes = await app.inject({
        method: 'DELETE',
        url: `/api/api-keys/${key.id}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(revokeRes.statusCode).toBe(200);

      // Key no longer appears in the list
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(
        listRes.json<{ data: { keys: unknown[] } }>().data.keys
      ).toHaveLength(0);
    });

    it('should return 409 if the key is already revoked', async () => {
      const { accessToken } = await registerAndLogin('revoke-twice@test.com');
      const createRes = await createApiKey(accessToken);
      const { key } = createRes.json<{ data: { key: { id: string } } }>().data;

      await app.inject({
        method: 'DELETE',
        url: `/api/api-keys/${key.id}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/api-keys/${key.id}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.statusCode).toBe(409);
    });

    it("should return 403 when revoking another user's key", async () => {
      const { accessToken: tokenA } = await registerAndLogin('rev-a@test.com');
      const { accessToken: tokenB } = await registerAndLogin('rev-b@test.com');

      const createRes = await createApiKey(tokenA);
      const { key } = createRes.json<{ data: { key: { id: string } } }>().data;

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/api-keys/${key.id}`,
        headers: { authorization: `Bearer ${tokenB}` },
      });
      expect(res.statusCode).toBe(403);
    });
  });

  // ── Authenticate with an API key ───────────────────────────

  describe('API key authentication', () => {
    it('should block API-key principals from key-management routes (REQUIRES_INTERACTIVE_AUTH)', async () => {
      const { accessToken } = await registerAndLogin('auth-key@test.com');
      const createRes = await createApiKey(accessToken);
      const { plaintext } = createRes.json<{ data: { plaintext: string } }>()
        .data;

      // API keys authenticate successfully but must not reach key-management
      const res = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${plaintext}` },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json()).toMatchObject({
        error: { code: 'REQUIRES_INTERACTIVE_AUTH' },
      });
    });

    it('should return 401 for an invalid key', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: 'Bearer grf_live_thisisnotavalidkey' },
      });
      expect(res.statusCode).toBe(401);
    });

    it('should return 401 for a revoked key', async () => {
      const { accessToken } = await registerAndLogin('auth-revoked@test.com');
      const createRes = await createApiKey(accessToken);
      const { key, plaintext } = createRes.json<{
        data: { key: { id: string }; plaintext: string };
      }>().data;

      // Revoke it
      await app.inject({
        method: 'DELETE',
        url: `/api/api-keys/${key.id}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      // Now try to use it
      const res = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${plaintext}` },
      });
      expect(res.statusCode).toBe(401);
    });

    it('should return 401 for an expired key', async () => {
      const { accessToken } = await registerAndLogin('auth-expired@test.com');

      // Create key that expired yesterday
      const yesterday = new Date(Date.now() - 86_400_000).toISOString();
      const createRes = await createApiKey(accessToken, {
        expiresAt: yesterday,
      });
      const { plaintext } = createRes.json<{ data: { plaintext: string } }>()
        .data;

      const res = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${plaintext}` },
      });
      expect(res.statusCode).toBe(401);
    });

    it('should return 401 when the key owner is on the Redis blocklist', async () => {
      const { accessToken } = await registerAndLogin('auth-blocked@test.com');
      const createRes = await createApiKey(accessToken);
      const { plaintext } = createRes.json<{ data: { plaintext: string } }>()
        .data;

      // Get the user's ID from the key list to add to blocklist
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      const keyRecord = listRes.json<{
        data: { keys: Array<{ userId: string }> };
      }>().data.keys[0];

      // Simulate admin disabling the user via Redis blocklist
      await redis.set(`blocklist:user:${keyRecord.userId}`, '1', 'EX', 300);

      const res = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${plaintext}` },
      });
      expect(res.statusCode).toBe(401);
    });

    it('should not grant permissions beyond those set at creation', async () => {
      const { accessToken } = await registerAndLogin('perms@test.com');

      // Create key with only read:profile — not write:users (admin permission)
      const createRes = await createApiKey(accessToken, {
        permissions: ['read:profile'],
      });
      const { plaintext } = createRes.json<{ data: { plaintext: string } }>()
        .data;

      // Try to hit an endpoint that requires write:users
      const res = await app.inject({
        method: 'GET',
        url: '/api/admin/users',
        headers: { authorization: `Bearer ${plaintext}` },
      });
      // Forbidden — key doesn't carry write:users even if user has the role
      expect(res.statusCode).toBe(403);
    });
  });

  // ── Org-scoped key ─────────────────────────────────────────

  describe('Org-scoped API key', () => {
    it('should create a key scoped to an org and reflect orgId in metadata', async () => {
      const { accessToken } = await registerAndLogin('org-key@test.com');
      const org = await createOrg(accessToken, 'Test Org', 'test-org');

      const res = await createApiKey(accessToken, { orgId: org.id });
      expect(res.statusCode).toBe(201);

      const { key } = res.json<{ data: { key: { orgId: string } } }>().data;
      expect(key.orgId).toBe(org.id);
    });
  });

  // ── Key limit enforcement ──────────────────────────────────

  describe('Key limit enforcement', () => {
    it('should return 409 API_KEY_LIMIT_REACHED when limit is exceeded', async () => {
      const { accessToken } = await registerAndLogin('limit@test.com');

      // Get the user's ID via the JWT — find user in DB
      const [userRow] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, 'limit@test.com'));

      // Insert fake non-revoked keys up to the configured limit directly to avoid API calls
      await db.insert(apiKeys).values(
        Array.from({ length: env.MAX_API_KEYS_PER_USER }, (_, i) => ({
          userId: userRow.id,
          name: `Fake Key ${i}`,
          prefix: 'grf_live_fa',
          keyHash: crypto
            .createHash('sha256')
            .update(`fake-key-${i}`)
            .digest('hex'),
          permissions: ['read:profile'],
        }))
      );

      // The 11th creation should be rejected
      const res = await createApiKey(accessToken, { name: 'One Too Many' });
      expect(res.statusCode).toBe(409);
      expect(res.json<{ error: { code: string } }>().error.code).toBe(
        'API_KEY_LIMIT_REACHED'
      );
    });

    it('should allow creation after a key is revoked (slot freed)', async () => {
      const { accessToken } = await registerAndLogin('limit-revoke@test.com');

      const [userRow] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, 'limit-revoke@test.com'));

      // Fill to limit
      await db.insert(apiKeys).values(
        Array.from({ length: env.MAX_API_KEYS_PER_USER }, (_, i) => ({
          userId: userRow.id,
          name: `Fake Key ${i}`,
          prefix: 'grf_live_fa',
          keyHash: crypto
            .createHash('sha256')
            .update(`fake-rev-${i}`)
            .digest('hex'),
          permissions: ['read:profile'],
        }))
      );

      // Revoke one
      await db
        .update(apiKeys)
        .set({ revokedAt: new Date() })
        .where(sql`user_id = ${userRow.id} AND name = 'Fake Key 0'`);

      // Now creation should succeed
      const res = await createApiKey(accessToken, { name: 'New Key' });
      expect(res.statusCode).toBe(201);
    });
  });

  // ── Admin endpoints ────────────────────────────────────────

  describe('Admin API key endpoints', () => {
    async function getAdminToken() {
      await registerAndLogin('admin@test.com');

      // Grant admin role directly
      const [userRow] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, 'admin@test.com'));

      // Use the admin API to elevate — or grant via DB directly using seed roles
      // Simpler: seed creates the 'admin' role; assign it via RBAC endpoint
      // But that itself needs admin. Grant via DB instead.
      await db.execute(
        sql`INSERT INTO user_roles (user_id, role_id)
            SELECT ${userRow.id}, id FROM roles WHERE name = 'admin'`
      );

      // Re-login to get a token that includes the admin role in claims
      await db
        .update(users)
        .set({ isVerified: true })
        .where(eq(users.email, 'admin@test.com'));

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'admin@test.com', password: 'Password1!' },
      });
      return loginRes.json<{ data: { accessToken: string } }>().data
        .accessToken;
    }

    it("should allow admin to list another user's API keys", async () => {
      const adminToken = await getAdminToken();
      const { accessToken: userToken } =
        await registerAndLogin('target@test.com');
      await createApiKey(userToken, { name: 'Target Key' });

      const [targetUser] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, 'target@test.com'));

      const res = await app.inject({
        method: 'GET',
        url: `/api/admin/users/${targetUser.id}/api-keys`,
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json<{ data: { keys: unknown[] } }>().data.keys).toHaveLength(
        1
      );
    });

    it("should allow admin to revoke another user's API key", async () => {
      const adminToken = await getAdminToken();
      const { accessToken: userToken } =
        await registerAndLogin('target2@test.com');
      const createRes = await createApiKey(userToken);
      const { key } = createRes.json<{ data: { key: { id: string } } }>().data;

      const [targetUser] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, 'target2@test.com'));

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/admin/users/${targetUser.id}/api-keys/${key.id}`,
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(res.statusCode).toBe(200);

      // Key is now unusable
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/api-keys',
        headers: { authorization: `Bearer ${userToken}` },
      });
      expect(
        listRes.json<{ data: { keys: unknown[] } }>().data.keys
      ).toHaveLength(0);
    });
  });
});
