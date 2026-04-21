import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import fastifyRateLimit from '@fastify/rate-limit';
import { env } from './config/env';
import { redis } from './db/redis';
import { onRequestLogger, onResponseLogger } from './middleware/request-logger';
import { logger } from './utils/logger';
import { authRoutes } from './routes/auth.routes';
import { oauthRoutes } from './routes/oauth.routes';
import { mfaRoutes } from './routes/mfa.routes';
import { buildErrorResponse } from './utils/response';
import { rbacRoutes } from './routes/rbac.routes';
import { adminRoutes } from './routes/admin.routes';
import { orgRoutes } from './routes/org.routes';
import { webhookRoutes } from './routes/webhook.routes';
import { apiKeyRoutes } from './routes/api-key.routes';
import { sessionRoutes } from './routes/session.routes';
import { pool } from './db/connection';
import { seedSystemData } from './db/seed';
import { startDeletionPurgeJob } from './jobs/deletion-purge.job';
import { startWebhookDeliveryJob } from './jobs/webhook-delivery.job';
import {
  httpRequestDuration,
  httpRequestsTotal,
  metricsRegistry,
} from './utils/metrics';
import { APP_VERSION } from './version';

export async function buildApp() {
  const app = Fastify({
    logger: false, // We use our own Pino logger, not Fastify's built-in
    // Assign a unique request ID to every request
    // This is what lets you trace a single request through all your logs
    genReqId: () => crypto.randomUUID(),
    requestIdHeader: 'x-request-id',
  });

  // ── Hooks — registered once during boot ────────────────
  app.addHook('onRequest', onRequestLogger);
  app.addHook('onResponse', onResponseLogger);

  app.addHook('onSend', (_request, reply, _payload, done) => {
    void reply.header('x-request-id', _request.id);
    done();
  });

  // ── Metrics — track HTTP request duration + count ──────
  app.addHook('onRequest', (request, _reply, done) => {
    // Store start time on request for duration calculation
    (request as unknown as Record<string, unknown>).__startTime =
      process.hrtime.bigint();
    done();
  });

  app.addHook('onResponse', (request, reply, done) => {
    const startTime = (request as unknown as Record<string, unknown>)
      .__startTime as bigint | undefined;
    if (startTime) {
      const duration =
        Number(process.hrtime.bigint() - startTime) / 1_000_000_000;
      // Use routeOptions.url for the parameterized route pattern (e.g. /api/users/:id/roles)
      // Falls back to request.url for routes without patterns (e.g. /health)
      const route = request.routeOptions?.url ?? request.url;
      const labels = {
        method: request.method,
        route,
        status_code: reply.statusCode.toString(),
      };
      httpRequestDuration.observe(labels, duration);
      httpRequestsTotal.inc(labels);
    }
    done();
  });

  // ── Plugins ────────────────────────────────────────────
  // CORS — controls which domains can call your API
  await app.register(cors, {
    origin: env.CORS_ORIGINS.split(',').map((o) => o.trim()),
    credentials: true,
  });

  // Helmet — sets secure HTTP headers automatically
  // Protects against clickjacking, MIME sniffing, and more
  await app.register(helmet);

  // Rate limiting — uses Redis for distributed counting
  // Works correctly across multiple server instances
  await app.register(fastifyRateLimit, {
    global: true,
    max: 100, // 100 requests
    timeWindow: '15 minutes', // per 15 minutes per IP
    redis,
    skipOnError: true, // Don't fail if Redis is down
    keyGenerator: (request) => {
      // Rate limit by IP
      // In production behind a load balancer use X-Forwarded-For
      return request.ip;
    },
    errorResponseBuilder: (_request, context) => {
      const response = buildErrorResponse(
        'RATE_LIMIT_EXCEEDED',
        `Too many requests. Please try again after ${Math.ceil(context.ttl / 1000)} seconds.`
      );

      // Attach statusCode as a hidden property.
      Object.defineProperty(response, 'statusCode', {
        value: 429,
        enumerable: false,
      });

      return response;
    },
  });

  // ── Seed system data ───────────────────────────────────
  // Idempotent — ensures roles + permissions exist on every boot
  await seedSystemData();

  // ── Background Jobs ────────────────────────────────────
  if (env.NODE_ENV !== 'test') {
    startDeletionPurgeJob();
    startWebhookDeliveryJob();
  }

  // ── Routes ─────────────────────────────────────────────
  app.get('/health', async (_request, reply) => {
    // Check database
    let dbStatus: 'ok' | 'degraded' = 'ok';
    try {
      const client = await pool.connect();
      await client.query('SELECT 1');
      client.release();
    } catch {
      dbStatus = 'degraded';
    }

    // Check Redis
    let redisStatus: 'ok' | 'degraded' = 'ok';
    try {
      await redis.ping();
    } catch {
      redisStatus = 'degraded';
    }

    const allHealthy = dbStatus === 'ok' && redisStatus === 'ok';

    return reply.status(allHealthy ? 200 : 503).send({
      status: allHealthy ? 'ok' : 'degraded',
      version: APP_VERSION,
      environment: env.NODE_ENV,
      timestamp: new Date().toISOString(),
      dependencies: {
        database: dbStatus,
        redis: redisStatus,
      },
    });
  });

  // ── Prometheus metrics ──────────────────────────────────
  // WARNING: Protect this endpoint in production — it exposes internal
  // system metrics. Use a reverse proxy, IP allowlist, or authenticate.
  app.get('/metrics', async (_request, reply) => {
    const metrics = await metricsRegistry.metrics();
    return reply
      .header('content-type', metricsRegistry.contentType)
      .send(metrics);
  });

  // Register all auth routes under /auth prefix
  void app.register(authRoutes, { prefix: '/auth' });
  void app.register(oauthRoutes, { prefix: '/auth' });
  void app.register(mfaRoutes, { prefix: '/auth' });
  void app.register(sessionRoutes, { prefix: '/auth' });

  void app.register(rbacRoutes, { prefix: '/api' });
  void app.register(adminRoutes, { prefix: '/api/admin' });
  void app.register(orgRoutes, { prefix: '/api/orgs' });
  void app.register(webhookRoutes, { prefix: '/api/orgs/:orgId/webhooks' });
  void app.register(apiKeyRoutes, { prefix: '/api' });

  // ── Error Handlers ──────────────────────────────────────
  app.setNotFoundHandler((request, reply) => {
    void reply
      .status(404)
      .send(
        buildErrorResponse(
          'NOT_FOUND',
          `Route ${request.method} ${request.url} not found`
        )
      );
  });

  // Global error handler — catches any unhandled errors
  app.setErrorHandler((error, request, reply) => {
    logger.error({ err: error, reqId: request.id }, 'Unhandled error');

    void reply
      .status(error.statusCode ?? 500)
      .send(
        buildErrorResponse(
          'INTERNAL_ERROR',
          env.NODE_ENV === 'production' ? 'Something went wrong' : error.message
        )
      );
  });

  return app;
}
