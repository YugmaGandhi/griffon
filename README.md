<div align="center">
  <h1>🔐 VaultAuth</h1>
  <p><strong>Lightweight, self-hostable, open-source authentication service</strong></p>
  <p>The auth infrastructure you own — no vendor lock-in, no monthly fees.</p>

  <p>
    <a href="https://github.com/YugmaGandhi/vaultauth/actions">
      <img src="https://github.com/YugmaGandhi/vaultauth/workflows/CI/badge.svg" alt="CI" />
    </a>
    <a href="https://github.com/YugmaGandhi/vaultauth/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" />
    </a>
    <img src="https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen" alt="Node 20+" />
    <img src="https://img.shields.io/badge/TypeScript-strict-blue" alt="TypeScript" />
  </p>
</div>

---

## What is VaultAuth?

VaultAuth is a production-grade authentication service you deploy yourself. It gives you:

- **Email + password auth** with Argon2id hashing
- **OAuth2** — Google, GitHub, Microsoft (extensible to any provider)
- **JWT** with RS256 signing and automatic refresh token rotation
- **RBAC** — roles and permissions embedded in tokens
- **Email flows** — verification and password reset
- **Rate limiting** — Redis-backed, distributed
- **Audit logs** — every auth event tracked
- **JavaScript SDK** — `@vaultauth/js` for easy integration

No vendor lock-in. No per-user pricing. Your data stays yours.

---

## Quick Start

### Prerequisites

- Node.js 20+
- Docker Desktop

### 1. Clone and install

```bash
git clone https://github.com/YugmaGandhi/vaultauth.git
cd vaultauth
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

----------

## API Overview

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Login, returns JWT + refresh token |
| POST | `/auth/logout` | Revoke refresh token |
| POST | `/auth/refresh` | Rotate refresh token |
| GET | `/auth/me` | Get current user |
| GET | `/auth/verify-email` | Verify email address |
| POST | `/auth/forgot-password` | Send reset email |
| POST | `/auth/reset-password` | Reset password |

### OAuth

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/oauth/providers` | List enabled providers |
| GET | `/auth/oauth/:provider` | Start OAuth flow |
| GET | `/auth/oauth/:provider/callback` | OAuth callback |

### Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/roles` | List all roles |
| GET | `/api/users/:id/roles` | Get user roles |
| POST | `/api/users/:id/roles` | Assign role |
| DELETE | `/api/users/:id/roles/:roleId` | Remove role |
| GET | `/api/admin/audit-logs` | Query audit logs |

----------

## JavaScript SDK

```bash
npm install @vaultauth/js

```

```typescript
import { VaultAuthClient, VaultAuthError } from '@vaultauth/js'

const client = new VaultAuthClient({
  baseUrl: 'https://your-vaultauth-instance.com'
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

VaultAuth is built with security first:

-   **Argon2id** password hashing (OWASP recommended, memory-hard)
-   **RS256 JWT** — asymmetric signing, public key shareable
-   **Single-use refresh tokens** — rotation on every use, reuse detection
-   **SHA-256** token storage — never raw tokens in database
-   **Brute force protection** — account lockout after 5 failures
-   **Rate limiting** — Redis-backed sliding window per IP
-   **Email enumeration prevention** — identical responses for unknown emails
-   **Audit logging** — every auth event with IP and metadata
-   **Security headers** — Helmet.js (CSP, HSTS, X-Frame-Options)

To report a vulnerability, see [SECURITY.md](./SECURITY.md).

----------

## Deployment

VaultAuth runs anywhere Docker runs.

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
docker build -t vaultauth ./server
docker run -p 3000:3000 --env-file server/.env vaultauth

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

```

----------

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) first.

**Good first issues:**

-   Add a new OAuth provider (Discord, Apple, Twitter)
-   Add webhook support for auth events
-   Build an admin dashboard UI

----------

## License

MIT — see [LICENSE](./LICENSE)

----------

<div align="center"> <p>Built in public by <a href="https://github.com/YugmaGandhi">Yugma Gandhi</a></p> </div>
