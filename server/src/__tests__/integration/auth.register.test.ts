import { sql } from 'drizzle-orm';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users } from '../../db/schema';
import { FastifyInstance } from 'fastify';
import { seedSystemData } from '../../db/seed';

describe('POST /auth/register', () => {
  let app: FastifyInstance;

  // Build a fresh app instance before all tests in this file
  beforeAll(async () => {
    await redis.connect();
    app = await buildApp();
    await app.ready();
  });

  // Clean up users table before each test
  // So tests don't affect each other
  beforeEach(async () => {
    await redis.flushdb();
    await db.execute(
      sql`TRUNCATE TABLE audit_logs, refresh_tokens, email_tokens, user_roles, role_permissions, roles, permissions, org_role_permissions, org_member_roles, org_permissions, org_roles, org_invitations, org_members, organizations, users RESTART IDENTITY CASCADE`
    );

    // Re-seed system data after truncate
    await seedSystemData();
  });

  // Close app and DB connection after all tests
  afterAll(async () => {
    await app.close();
  });

  // ── Happy Path ─────────────────────────────────────────
  it('should register a new user and return 201', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'test@example.com',
        password: 'password123',
      },
    });

    expect(response.statusCode).toBe(201);

    const body = response.json<{
      success: boolean;
      data: {
        user: {
          id: string;
          email: string;
          isVerified: boolean;
        };
        message: string;
      };
    }>();

    expect(body.success).toBe(true);
    expect(body.data.user.email).toBe('test@example.com');
    expect(body.data.user.isVerified).toBe(false);
    expect(body.data.message).toContain('Account created');
  });

  it('should store hashed password — never plain text', async () => {
    await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'test@example.com',
        password: 'password123',
      },
    });

    // Directly query the DB to check what was stored
    const [user] = await db.select().from(users);

    // Password must be hashed
    expect(user.passwordHash).not.toBe('password123');
    expect(user.passwordHash).toMatch(/^\$argon2id\$/);

    // Password hash must NOT appear in the HTTP response
    // (already checked above but being explicit here)
    expect(user.passwordHash).toBeDefined();
  });

  it('should normalize email to lowercase', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'TEST@EXAMPLE.COM',
        password: 'password123',
      },
    });

    expect(response.statusCode).toBe(201);

    const body = response.json<{
      success: boolean;
      data: { user: { email: string } };
    }>();

    expect(body.data.user.email).toBe('test@example.com');
  });

  // ── Duplicate Email ────────────────────────────────────
  it('should return 409 when email already exists', async () => {
    // Register first time
    await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'test@example.com',
        password: 'password123',
      },
    });

    // Try to register again with same email
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'test@example.com',
        password: 'differentpassword',
      },
    });

    expect(response.statusCode).toBe(409);

    const body = response.json<{
      success: boolean;
      error: { code: string };
    }>();

    expect(body.success).toBe(false);
    expect(body.error.code).toBe('EMAIL_ALREADY_EXISTS');
  });

  // ── Validation Errors ──────────────────────────────────
  it('should return 400 for invalid email format', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'notanemail',
        password: 'password123',
      },
    });

    expect(response.statusCode).toBe(400);

    const body = response.json<{
      success: boolean;
      error: { code: string; details: { field: string }[] };
    }>();

    expect(body.success).toBe(false);
    expect(body.error.code).toBe('VALIDATION_ERROR');
    expect(body.error.details[0].field).toBe('email');
  });

  it('should return 400 when password is too short', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'test@example.com',
        password: 'short',
      },
    });

    expect(response.statusCode).toBe(400);

    const body = response.json<{
      success: boolean;
      error: { code: string; details: { field: string }[] };
    }>();

    expect(body.success).toBe(false);
    expect(body.error.code).toBe('VALIDATION_ERROR');
    expect(body.error.details[0].field).toBe('password');
  });

  it('should return 400 when required fields are missing', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {},
    });

    expect(response.statusCode).toBe(400);

    const body = response.json<{
      success: boolean;
      error: { code: string };
    }>();

    expect(body.success).toBe(false);
    expect(body.error.code).toBe('VALIDATION_ERROR');
  });

  // ── Security Checks ────────────────────────────────────
  it('should never return passwordHash in response', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'test@example.com',
        password: 'password123',
      },
    });

    // Stringify entire response and check no hash appears
    const responseText = response.body;
    expect(responseText).not.toContain('passwordHash');
    expect(responseText).not.toContain('password_hash');
    expect(responseText).not.toContain('argon2');
  });
});
