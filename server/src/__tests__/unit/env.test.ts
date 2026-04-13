import { ZodIssue } from 'zod';
import { envSchema } from '../../config/env';

// Single source of truth for valid test env
// When schema adds a required field — update HERE only
const validEnv = {
  DATABASE_URL: 'postgresql://user:pass@localhost:5433/test',
  REDIS_URL: 'redis://localhost:6380',
  NODE_ENV: 'test' as const,
  JWT_PRIVATE_KEY: 'dummy-private-key-for-testing',
  JWT_PUBLIC_KEY: 'dummy-public-key-for-testing',
  EMAIL_FROM: 'noreply@griffon.dev',
  APP_BASE_URL: 'http://localhost:3000',
};

describe('Environment Configuration', () => {
  it('should load valid environment variables successfully', () => {
    const result = envSchema.safeParse(validEnv);
    expect(result.success).toBe(true);
  });

  it('should fail when DATABASE_URL is missing', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { DATABASE_URL: _DATABASE_URL, ...rest } = validEnv;
    const result = envSchema.safeParse(rest);

    expect(result.success).toBe(false);
    if (!result.success) {
      const fields = result.error.issues.map((i: ZodIssue) => i.path[0]);
      expect(fields).toContain('DATABASE_URL');
    }
  });

  it('should fail when REDIS_URL is missing', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { REDIS_URL: _REDIS_URL, ...rest } = validEnv;
    const result = envSchema.safeParse(rest);

    expect(result.success).toBe(false);
    if (!result.success) {
      const fields = result.error.issues.map((i: ZodIssue) => i.path[0]);
      expect(fields).toContain('REDIS_URL');
    }
  });

  it('should use default PORT of 3000 when not set', () => {
    const result = envSchema.safeParse(validEnv);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.PORT).toBe(3000);
    }
  });

  it('should reject invalid NODE_ENV values', () => {
    const result = envSchema.safeParse({
      ...validEnv,
      NODE_ENV: 'staging',
    });

    expect(result.success).toBe(false);
  });

  it('should coerce PORT from string to number', () => {
    const result = envSchema.safeParse({
      ...validEnv,
      PORT: '4000', // string — should be coerced to number
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.PORT).toBe(4000);
      expect(typeof result.data.PORT).toBe('number');
    }
  });

  it('should fail when JWT_PRIVATE_KEY is missing', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { JWT_PRIVATE_KEY: _JWT_PRIVATE_KEY, ...rest } = validEnv;
    const result = envSchema.safeParse(rest);

    expect(result.success).toBe(false);
    if (!result.success) {
      const fields = result.error.issues.map((i: ZodIssue) => i.path[0]);
      expect(fields).toContain('JWT_PRIVATE_KEY');
    }
  });

  it('should fail when JWT_PUBLIC_KEY is missing', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { JWT_PUBLIC_KEY: _JWT_PUBLIC_KEY, ...rest } = validEnv;
    const result = envSchema.safeParse(rest);

    expect(result.success).toBe(false);
    if (!result.success) {
      const fields = result.error.issues.map((i: ZodIssue) => i.path[0]);
      expect(fields).toContain('JWT_PUBLIC_KEY');
    }
  });
});
