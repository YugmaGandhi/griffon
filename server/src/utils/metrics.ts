import client from 'prom-client';

// ── Default metrics ──────────────────────────────────────
// Collects Node.js process metrics: memory, CPU, event loop lag,
// active handles, GC pauses. These are standard for any Node service.
client.collectDefaultMetrics({ prefix: 'griffon_' });

// ── HTTP metrics ─────────────────────────────────────────
export const httpRequestDuration = new client.Histogram({
  name: 'griffon_http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'] as const,
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
});

export const httpRequestsTotal = new client.Counter({
  name: 'griffon_http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'] as const,
});

// ── Auth event metrics ───────────────────────────────────
export const authEventsTotal = new client.Counter({
  name: 'griffon_auth_events_total',
  help: 'Total number of authentication events',
  labelNames: ['event'] as const,
});

// ── Active sessions gauge ────────────────────────────────
export const activeSessions = new client.Gauge({
  name: 'griffon_active_sessions',
  help: 'Number of active (non-revoked, non-expired) refresh tokens',
});

// ── Convenience: get the registry for /metrics endpoint ──
export const metricsRegistry = client.register;
