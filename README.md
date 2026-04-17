<div align="center">
  <h1>🔐 Griffon</h1>
  <p><strong>Lightweight, self-hostable, open-source authentication service</strong></p>
  <p>The auth infrastructure you own — no vendor lock-in, no monthly fees.</p>

  <p>
    <a href="https://github.com/YugmaGandhi/griffon/actions">
      <img src="https://github.com/YugmaGandhi/griffon/workflows/CI/badge.svg" alt="CI" />
    </a>
    <a href="https://github.com/YugmaGandhi/griffon/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" />
    </a>
    <img src="https://img.shields.io/badge/node-%3E%3D24.0.0-brightgreen" alt="Node 24+" />
    <img src="https://img.shields.io/badge/TypeScript-strict-blue" alt="TypeScript" />
  </p>
</div>

---

## What is Griffon?

Griffon is a production-grade authentication service you deploy yourself. It gives you:

- **Email + password auth** with Argon2id hashing
- **OAuth2** — Google, GitHub, Microsoft (extensible to any provider)
- **MFA** — TOTP-based two-factor authentication with QR code enrollment, recovery codes, and org-level enforcement
- **JWT** with RS256 signing and automatic refresh token rotation
- **RBAC** — roles and permissions embedded in tokens
- **Multi-organization support** — users belong to multiple orgs, org-scoped roles and permissions in every token
- **Session management** — list and revoke active sessions, self-service or admin-controlled
- **User management** — admin API to create, update, disable, enable, and force-delete users
- **Account deletion** — GDPR-compliant self-service deletion with 30-day grace period and admin force-delete
- **Webhook events** — subscribe to auth and org events via HTTPS callbacks, HMAC-signed with exponential backoff retry
- **Email flows** — verification and password reset
- **Rate limiting** — Redis-backed, distributed
- **Audit logs** — every auth event tracked
- **JavaScript SDK** — `@griffon/js` for easy integration

No vendor lock-in. No per-user pricing. Your data stays yours.

---

## Quick Start

### Prerequisites

- Node.js 20+
- Docker Desktop

### 1. Clone and install

```bash
git clone https://github.com/YugmaGandhi/griffon.git
cd griffon
npm install

```

### 2. Start infrastructure

```bash
npm run infra:up

```

This starts PostgreSQL, Redis, and Mailpit (email catcher) via Docker.

### 3. Configure environment

```bash
cp server/.env.example server/.env

```

Generate RSA keys for JWT signing:

```bash
cd server && npm run gen:keys

```

Paste the output into `server/.env`.

### 4. Run migrations

```bash
cd server && npm run db:migrate

```

### 5. Start the server

```bash
npm run dev

```

Server runs at `http://localhost:3000`. Visit `http://localhost:3000/health` to confirm.

> **Note:** On first boot, Griffon automatically seeds the default roles, permissions, and role-permission mappings. No manual seed step is required.

----------

## API Overview

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Login — returns JWT + refresh token, or MFA challenge if MFA is enrolled |
| POST | `/auth/logout` | Revoke refresh token |
| POST | `/auth/refresh` | Rotate refresh token |
| GET | `/auth/me` | Get current user |
| GET | `/auth/verify-email` | Verify email address |
| POST | `/auth/forgot-password` | Send reset email |
| POST | `/auth/reset-password` | Reset password |
| POST | `/auth/set-active-org` | Switch active org, returns new token pair |
| POST | `/auth/accept-invitation` | Accept org invitation |
| GET | `/auth/sessions` | List active sessions for current user |
| DELETE | `/auth/sessions/:id` | Revoke a specific session |
| DELETE | `/auth/sessions` | Revoke all sessions (sign out everywhere) |
| POST | `/auth/account/delete` | Request account deletion (30-day grace period) |
| DELETE | `/auth/account/delete` | Cancel a pending deletion request |

### MFA

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/mfa/setup` | Start enrollment — returns TOTP secret, QR code, and recovery codes |
| POST | `/auth/mfa/verify-setup` | Confirm enrollment with first TOTP code |
| POST | `/auth/mfa/verify` | Complete two-step login with TOTP or recovery code |
| GET | `/auth/mfa/status` | Get MFA enrollment state and remaining recovery codes |
| DELETE | `/auth/mfa` | Disable MFA (requires valid TOTP code) |
| POST | `/auth/mfa/recovery-codes` | Regenerate recovery codes (requires valid TOTP code) |
| GET | `/api/orgs/:orgId/mfa-policy` | Get org MFA enforcement policy |
| PUT | `/api/orgs/:orgId/mfa-policy` | Enable or disable MFA enforcement for an org (owner only) |
| DELETE | `/api/admin/users/:id/mfa` | Admin force-disable MFA for a user |

### Organizations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/orgs` | Create organization |
| GET | `/api/orgs` | List user's organizations |
| GET | `/api/orgs/:orgId` | Get org details |
| PATCH | `/api/orgs/:orgId` | Update org name, slug, logo |
| DELETE | `/api/orgs/:orgId` | Delete org (owner only) |
| GET | `/api/orgs/:orgId/members` | List members |
| PATCH | `/api/orgs/:orgId/members/:userId` | Update member role |
| DELETE | `/api/orgs/:orgId/members/:userId` | Remove member |
| POST | `/api/orgs/:orgId/members/invite` | Invite member by email |
| GET | `/api/orgs/:orgId/invitations` | List pending invitations |
| DELETE | `/api/orgs/:orgId/invitations/:id` | Revoke invitation |
| PATCH | `/api/orgs/:orgId/transfer-ownership` | Transfer ownership |

### OAuth

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/oauth/providers` | List enabled providers |
| GET | `/auth/oauth/:provider` | Start OAuth flow |
| GET | `/auth/oauth/:provider/callback` | OAuth callback |

### Admin — User Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/users` | List users (paginated, filter by email/status) |
| POST | `/api/admin/users` | Create a user (platform admin only) |
| PATCH | `/api/admin/users/:id` | Update user email or verification status |
| POST | `/api/admin/users/:id/disable` | Disable user — blocks login + invalidates sessions |
| POST | `/api/admin/users/:id/enable` | Re-enable a disabled user |
| GET | `/api/admin/users/:id/sessions` | View active sessions for a user |
| DELETE | `/api/admin/users/:id/sessions` | Revoke all sessions for a user |
| POST | `/api/admin/users/:id/delete` | Permanently delete a user (immediate, irreversible) |

### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/orgs/:orgId/webhooks` | Register webhook endpoint (returns signing secret once) |
| GET | `/api/orgs/:orgId/webhooks` | List endpoints for an org |
| PATCH | `/api/orgs/:orgId/webhooks/:id` | Update URL, events, or active state |
| DELETE | `/api/orgs/:orgId/webhooks/:id` | Delete endpoint (cascades deliveries) |
| GET | `/api/orgs/:orgId/webhooks/:id/deliveries` | View delivery log |
| POST | `/api/orgs/:orgId/webhooks/:id/test` | Send a test event |

**Events emitted:** `user.login`, `org.member.joined`, `org.member.removed`, `webhook.test`

### Admin — RBAC & Audit

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/roles` | List all roles |
| GET | `/api/users/:id/roles` | Get user roles |
| POST | `/api/users/:id/roles` | Assign role |
| DELETE | `/api/users/:id/roles/:roleId` | Remove role |
| GET | `/api/admin/audit-logs` | Query audit logs |
| GET | `/metrics` | Prometheus metrics |

### Default Roles & Permissions

Griffon ships with system roles and permissions that are seeded automatically on every boot. These are required for the application to function — do not delete them.

**Roles:**

| Role | Description |
|------|-------------|
| `user` | Assigned to every new user on registration |
| `moderator` | Can view users and audit logs |
| `admin` | Full system access |

**Permissions:**

| Permission | user | moderator | admin |
|------------|:----:|:---------:|:-----:|
| `read:profile` | ✓ | ✓ | ✓ |
| `write:profile` | ✓ | ✓ | ✓ |
| `read:users` | | ✓ | ✓ |
| `write:users` | | | ✓ |
| `read:roles` | | ✓ | ✓ |
| `write:roles` | | | ✓ |
| `read:audit-logs` | | ✓ | ✓ |

You can assign additional roles to users via the API. Role-permission mappings can be customized after initial setup.

----------

## JavaScript SDK

```bash
npm install @griffon/js

```

```typescript
import { GriffonClient, GriffonError } from '@griffon/js'

const client = new GriffonClient({
  baseUrl: 'https://your-griffon-instance.com'
})

// Register
await client.register('user@example.com', 'password123')

// Login — tokens stored automatically
const { user } = await client.login('user@example.com', 'password123')

// Authenticated requests — token attached automatically
const me = await client.getMe()

// Token refresh happens automatically when expired

// OAuth
window.location.href = client.getOAuthUrl('google')

// Logout
await client.logout()

```

----------

## OAuth Setup

### Google

1.  Go to [Google Cloud Console](https://console.cloud.google.com/)
2.  Create OAuth 2.0 credentials
3.  Add redirect URI: `http://localhost:3000/auth/oauth/google/callback`
4.  Add to `.env`:

```bash
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret

```

### GitHub

1.  Go to [GitHub Developer Settings](https://github.com/settings/applications/new)
2.  Set callback URL: `http://localhost:3000/auth/oauth/github/callback`
3.  Add to `.env`:

```bash
GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret

```

### Adding a new provider

Add 8 lines to `server/src/config/oauth-providers.ts`:

```typescript
discord: env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET
  ? {
      name: 'discord',
      authUrl: 'https://discord.com/oauth2/authorize',
      tokenUrl: 'https://discord.com/api/oauth2/token',
      profileUrl: 'https://discord.com/api/users/@me',
      scopes: ['identify', 'email'],
      clientId: env.DISCORD_CLIENT_ID,
      clientSecret: env.DISCORD_CLIENT_SECRET,
      getProfile: (data) => ({ id: String(data.id), email: String(data.email) }),
    }
  : null,

```

Zero route changes needed.

----------

## Security

Griffon is built with security first:

-   **Argon2id** password hashing (OWASP recommended, memory-hard)
-   **RS256 JWT** — asymmetric signing, public key shareable
-   **TOTP MFA** — AES-256-GCM encrypted secrets at rest, single-use recovery codes, short-lived challenge tokens
-   **Single-use refresh tokens** — rotation on every use, reuse detection
-   **SHA-256** token storage — never raw tokens in database
-   **Brute force protection** — account lockout after 5 failures
-   **Rate limiting** — Redis-backed sliding window per IP
-   **Email enumeration prevention** — identical responses for unknown emails
-   **Audit logging** — every auth event with IP and metadata
-   **Security headers** — Helmet.js (CSP, HSTS, X-Frame-Options)

To report a vulnerability, see [SECURITY.md](./SECURITY.md).

----------

## Monitoring

Griffon exposes a Prometheus-compatible `/metrics` endpoint for observability.

**Available metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `griffon_http_request_duration_seconds` | Histogram | Request duration by method, route, status |
| `griffon_http_requests_total` | Counter | Total requests by method, route, status |
| `griffon_auth_events_total` | Counter | Auth events (login_success, login_failed, register, logout, account_locked, etc.) |
| `griffon_active_sessions` | Gauge | Active refresh token count |
| `griffon_nodejs_*` | Various | Node.js process metrics (memory, CPU, event loop, GC) |

**Grafana dashboard example:**

```promql
# Request rate
rate(griffon_http_requests_total[5m])

# Login failure rate (brute force detection)
rate(griffon_auth_events_total{event="login_failed"}[5m])

# P95 latency
histogram_quantile(0.95, rate(griffon_http_request_duration_seconds_bucket[5m]))
```

> **Production warning:** The `/metrics` endpoint is unauthenticated by default. Protect it with a reverse proxy, IP allowlist, or network policy. Do not expose it to the public internet.

----------

## Deployment

Griffon runs anywhere Docker runs.

### Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/)

```bash
railway up

```

### Fly.io

```bash
fly launch
fly secrets set JWT_PRIVATE_KEY=... JWT_PUBLIC_KEY=...
fly deploy

```

### Docker

```bash
docker build -t griffon ./server
docker run -p 3000:3000 --env-file server/.env griffon

```

----------

## Development

```bash
# Start infrastructure
npm run infra:up

# Start server with hot reload
npm run dev

# Run tests
npm test

# Run SDK tests
cd sdk && npm test

# View emails (Mailpit)
open http://localhost:8025

# View database (Drizzle Studio)
cd server && npm run db:studio

```

### Dev utilities

```bash
# Manually verify a user email
cd server && npm run dev:verify user@example.com

# Promote user to admin
cd server && npm run dev:make-admin user@example.com

# Generate RSA keypair
cd server && npm run gen:keys

# Re-seed system roles and permissions (runs automatically on boot)
cd server && npm run db:seed

```

----------

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) first.

**Good first issues:**

-   Add a new OAuth provider (Discord, Apple, Twitter)
-   Add rate-limit configuration per route
-   Build an admin dashboard UI

----------

## License

MIT — see [LICENSE](./LICENSE)

----------

<div align="center"> <p>Built in public by <a href="https://github.com/YugmaGandhi">Yugma Gandhi</a></p> </div>
