import { z } from 'zod';
import dotenv from 'dotenv';

// Load .env file before validation
dotenv.config();

// Export schema separately so tests can use it directly
// without triggering the process.exit logic below
export const envSchema = z
  .object({
    // Server
    NODE_ENV: z
      .enum(['development', 'test', 'production'])
      .default('development'),
    PORT: z.coerce.number().default(3000),
    HOST: z.string().default('0.0.0.0'),
    LOG_LEVEL: z
      .enum(['trace', 'debug', 'info', 'warn', 'error'])
      .default('info'),

    // Database
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

    // Redis
    REDIS_URL: z.string().min(1, 'REDIS_URL is required'),

    // CORS
    CORS_ORIGINS: z.string().default('http://localhost:3001'),

    // JWT
    JWT_PRIVATE_KEY: z.string().min(1, 'JWT_PRIVATE_KEY is required'),
    JWT_PUBLIC_KEY: z.string().min(1, 'JWT_PUBLIC_KEY is required'),
    JWT_ACCESS_EXPIRY: z.string().default('15m'),
    JWT_REFRESH_EXPIRY: z.string().default('30d'),
    JWT_ISSUER: z.string().default('griffon'),

    // Email
    EMAIL_PROVIDER: z.enum(['smtp', 'resend']).default('smtp'),
    EMAIL_FROM: z.string().min(1, 'EMAIL_FROM is required'),
    EMAIL_FROM_NAME: z.string().default('Griffon'),
    SMTP_HOST: z.string().optional(),
    SMTP_PORT: z.coerce.number().default(587),
    SMTP_USER: z.string().optional(),
    SMTP_PASS: z.string().optional(),
    RESEND_API_KEY: z.string().optional(),
    APP_BASE_URL: z.string().min(1, 'APP_BASE_URL is required'),

    // OAuth Providers
    GOOGLE_CLIENT_ID: z.string().optional(),
    GOOGLE_CLIENT_SECRET: z.string().optional(),
    GITHUB_CLIENT_ID: z.string().optional(),
    GITHUB_CLIENT_SECRET: z.string().optional(),
    MICROSOFT_CLIENT_ID: z.string().optional(),
    MICROSOFT_CLIENT_SECRET: z.string().optional(),
    // Organizations
    ALLOW_ORG_CREATION: z
      .enum(['true', 'false'])
      .default('true')
      .transform((v) => v === 'true'),
    MAX_ORGS_PER_USER: z.coerce.number().default(10),

    OAUTH_CALLBACK_BASE_URL: z.string().default('http://localhost:3000'),
    OAUTH_SUCCESS_REDIRECT: z
      .string()
      .default('http://localhost:3001/dashboard'),
    OAUTH_FAILURE_REDIRECT: z.string().default('http://localhost:3001/login'),

    // Webhook — 32-byte hex key for AES-256-GCM encryption of signing secrets.
    // In production: generate with `openssl rand -hex 32` and set as secret.
    // The dev default is intentionally insecure — production deploys must override.
    WEBHOOK_SECRET_KEY: z
      .string()
      .regex(
        /^[0-9a-fA-F]{64}$/,
        'WEBHOOK_SECRET_KEY must be a 64-char hex string (32 bytes)'
      )
      .default(
        '0000000000000000000000000000000000000000000000000000000000000000'
      ),
  })
  .superRefine((env, ctx) => {
    // Block the all-zero placeholder in production — the dev default
    // exists so local boot succeeds, but it must never reach prod.
    if (env.NODE_ENV === 'production' && /^0+$/.test(env.WEBHOOK_SECRET_KEY)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['WEBHOOK_SECRET_KEY'],
        message:
          'WEBHOOK_SECRET_KEY is set to the insecure default. Generate a real key with `openssl rand -hex 32`.',
      });
    }
  });

export type Env = z.infer<typeof envSchema>;

// This block only runs when the module is loaded by the real app
// Tests import envSchema directly — they never trigger this
// Validate on import — crashes with clear error if invalid
const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ Invalid environment variables:');
  parsed.error.issues.forEach((issue) => {
    console.error(`   ${issue.path.join('.')}: ${issue.message}`);
  });
  process.exit(1);
}

export const env = parsed.data;
