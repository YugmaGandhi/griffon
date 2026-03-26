import { buildApp } from './app';
import { env } from './config/env';
import { pool } from './db/connection';
import { connectRedis } from './db/redis';
import { logger } from './utils/logger';

async function start() {
  // Test database connection
  try {
    const client = await pool.connect();
    client.release();
    logger.info('Database connected');
  } catch (err) {
    logger.error({ err }, 'Database connection failed');
    process.exit(1);
  }

  // Connect Redis
  try {
    await connectRedis();
  } catch (err) {
    logger.error({ err }, 'Redis connection failed');
    process.exit(1);
  }

  const app = await buildApp();

  try {
    await app.listen({
      port: env.PORT,
      host: env.HOST,
    });
    logger.info({ port: env.PORT, env: env.NODE_ENV }, 'Server started');
  } catch (err) {
    logger.error({ err }, 'Server failed to start');
    process.exit(1);
  }

  // ── Graceful Shutdown ───────────────────────────────────
  // When the server receives SIGINT (Ctrl+C) or SIGTERM (Docker stop),
  // it stops accepting new requests and waits for existing ones to finish
  // before closing. Without this, requests mid-flight would be cut off.
  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutting down gracefully');
    await app.close();
    logger.info('Server closed');
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

void start();
