import { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { redis } from '../../db/redis';

describe('App — health, 404, error handler', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    await redis.connect();
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    await redis.flushdb();
  });

  afterAll(async () => {
    await app.close();
  });

  // ── Health endpoint ────────────────────────────────────
  describe('GET /health', () => {
    it('should return 200 with ok status when all dependencies are healthy', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{
        status: string;
        version: string;
        environment: string;
        timestamp: string;
        dependencies: { database: string; redis: string };
      }>();
      expect(body.status).toBe('ok');
      expect(body.version).toBe('1.0.0');
      expect(body.dependencies.database).toBe('ok');
      expect(body.dependencies.redis).toBe('ok');
      expect(body.timestamp).toBeDefined();
    });
  });

  // ── 404 handler ────────────────────────────────────────
  describe('Not Found handler', () => {
    it('should return 404 with standard error shape for unknown route', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/this/route/does/not/exist',
      });

      expect(res.statusCode).toBe(404);
      const body = res.json<{
        success: boolean;
        error: { code: string; message: string };
      }>();
      expect(body.success).toBe(false);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toContain('not found');
    });

    it('should include method and URL in 404 message', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/nonexistent',
      });

      expect(res.statusCode).toBe(404);
      const body = res.json<{
        error: { message: string };
      }>();
      expect(body.error.message).toContain('POST');
      expect(body.error.message).toContain('/api/nonexistent');
    });
  });

  // ── Metrics endpoint ────────────────────────────────────
  describe('GET /metrics', () => {
    it('should return Prometheus metrics', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/metrics',
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('text/plain');
      // Should contain default Node.js metrics
      expect(res.body).toContain('griffon_nodejs');
      // Should contain our custom HTTP metrics
      expect(res.body).toContain('griffon_http_request_duration_seconds');
      expect(res.body).toContain('griffon_http_requests_total');
      // Should contain auth event metrics
      expect(res.body).toContain('griffon_auth_events_total');
    });
  });

  // ── X-Request-ID ───────────────────────────────────────
  describe('X-Request-ID header', () => {
    it('should include x-request-id in response headers', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
      });

      expect(res.headers['x-request-id']).toBeDefined();
      expect(typeof res.headers['x-request-id']).toBe('string');
    });
  });
});
