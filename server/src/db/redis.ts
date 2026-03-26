import Redis from 'ioredis';
import { env } from '../config/env';
import { createLogger } from '../utils/logger';

const log = createLogger('Redis');

export const redis = new Redis(env.REDIS_URL, {
  // Retry connection up to 3 times before giving up
  maxRetriesPerRequest: 3,
  // Don't crash the app if Redis is temporarily unavailable
  enableOfflineQueue: false,
  lazyConnect: true,
});

redis.on('connect', () => {
  log.info('Redis connected');
});

redis.on('error', (err) => {
  log.error({ err }, 'Redis error');
});

redis.on('close', () => {
  log.warn('Redis connection closed');
});

export async function connectRedis(): Promise<void> {
  await redis.connect();
}

export async function disconnectRedis(): Promise<void> {
  await redis.quit();
}
