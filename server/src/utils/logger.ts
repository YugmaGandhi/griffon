import pino from 'pino';
import { env } from '../config/env';

// Development — pretty printed, colorized, human readable
// Production — raw JSON, machine readable, goes to log aggregator
export const logger = pino({
  level: env.LOG_LEVEL,
  ...(env.NODE_ENV === 'development' && {
    transport: {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'HH:MM:ss',
        ignore: 'pid,hostname',
        messageFormat: '{msg} {reqId}',
      },
    },
  }),
  // Redact sensitive fields — these will show as [Redacted] in logs
  // CRITICAL: never log passwords, tokens, or keys
  redact: {
    paths: [
      'password',
      'passwordHash',
      'token',
      'accessToken',
      'refreshToken',
      'authorization',
      '*.password',
      '*.token',
    ],
    censor: '[Redacted]',
  },
});

// Child logger factory — adds context to every log in a module
// Usage: const log = createLogger('AuthService')
// Output: { module: 'AuthService', msg: '...' }
export function createLogger(module: string) {
  return logger.child({ module });
}
