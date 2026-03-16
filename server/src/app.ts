import Fastify from 'fastify'
import cors from '@fastify/cors'
import helmet from '@fastify/helmet'
import { env } from './config/env'

export function buildApp() {
  const app = Fastify({
    logger: {
      level: env.LOG_LEVEL,
      ...(env.NODE_ENV === 'development' && {
        transport: {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'HH:MM:ss',
            ignore: 'pid,hostname',
          },
        },
      }),
    },
    // Assign a unique request ID to every request
    // This is what lets you trace a single request through all your logs
    genReqId: () => crypto.randomUUID(),
    requestIdHeader: 'x-request-id',
  })

  // ── Plugins ────────────────────────────────────────────
  // CORS — controls which domains can call your API
  app.register(cors, {
    origin: env.CORS_ORIGINS.split(',').map((o) => o.trim()),
    credentials: true,
  })

  // Helmet — sets secure HTTP headers automatically
  // Protects against clickjacking, MIME sniffing, and more
  app.register(helmet)

  // ── Routes ─────────────────────────────────────────────
  // Health check — first real endpoint
  app.get('/health', async (_request, reply) => {
    return reply.send({
      status: 'ok',
      version: '1.0.0',
      environment: env.NODE_ENV,
      timestamp: new Date().toISOString(),
    })
  })

  // 404 handler — catches any route that doesn't exist
  app.setNotFoundHandler((request, reply) => {
    reply.status(404).send({
      success: false,
      error: {
        code: 'NOT_FOUND',
        message: `Route ${request.method} ${request.url} not found`,
      },
    })
  })

  // Global error handler — catches any unhandled errors
  app.setErrorHandler((error, request, reply) => {
    app.log.error({ err: error, reqId: request.id }, 'Unhandled error')

    reply.status(error.statusCode ?? 500).send({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message:
          env.NODE_ENV === 'production'
            ? 'Something went wrong'
            : error.message,
      },
    })
  })

  return app
}