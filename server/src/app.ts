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
import { buildErrorResponse } from './utils/response';

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

  // ── Routes ─────────────────────────────────────────────
  // Health check — first real endpoint
  app.get('/health', async (_request, reply) => {
    return reply.send({
      status: 'ok',
      version: '1.0.0',
      environment: env.NODE_ENV,
      timestamp: new Date().toISOString(),
    });
  });

  // Register all auth routes under /auth prefix
  await app.register(authRoutes, { prefix: '/auth' });
  await app.register(oauthRoutes, { prefix: '/auth' });

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
