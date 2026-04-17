# Contributing to Griffon

Thank you for your interest in contributing. This guide covers everything
you need to get started.

---

## Development Setup

### Prerequisites

- Node.js 24+
- Docker Desktop
- Git

### Steps

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/griffon.git
cd griffon

# 2. Install dependencies
npm install

# 3. Start infrastructure
npm run infra:up

# 4. Configure environment
cp server/.env.example server/.env
cd server && npm run gen:keys
# Paste generated keys into server/.env

# Generate MFA and webhook encryption keys
openssl rand -hex 32  # → MFA_ENCRYPTION_KEY
openssl rand -hex 32  # → WEBHOOK_SECRET_KEY (must differ from MFA key)

# 5. Run migrations
cd server && npm run db:migrate

# 6. Verify everything works
npm run dev
curl http://localhost:3000/health

# System roles and permissions are seeded automatically on boot.
# To re-seed manually: cd server && npm run db:seed

```

----------

## Project Structure

```
griffon/
  server/              # Fastify API
    src/
      routes/          # HTTP handlers — thin, delegate to services
      services/        # Business logic
      repositories/    # Database queries
      middleware/      # authenticate, authorize, rate-limit
      jobs/            # Background jobs (purge, cleanup)
      db/              # Drizzle schema + migrations
      config/          # Environment validation
      utils/           # Shared utilities
  sdk/                 # @griffon/js npm package
  bruno/               # API collection for testing
  docs/                # Documentation
  .github/             # CI/CD workflows

```

## Architecture Rules

-   **Routes** — parse request, call service, send response. No DB queries.
-   **Services** — business logic only. No HTTP concerns.
-   **Repositories** — database queries only. No business logic.
-   **Never** return `passwordHash` in any response.
-   **Always** use typed errors (`AppError` subclasses).
-   **Always** use response helpers (`sendSuccess`, `sendError`).

----------

## Making Changes

### Branch naming

```
feat/add-discord-oauth
fix/refresh-token-expiry
chore/upgrade-dependencies
docs/deployment-guide
test/rbac-coverage

```

### Commit messages (Conventional Commits)

```
feat(auth): add Discord OAuth provider
fix(tokens): correct refresh token expiry calculation
test(rbac): add permission scope validation tests
chore(deps): upgrade jose to v5.0.0

```

### PR requirements

-   CI must pass (lint + tests + typecheck)
-   Include a description of what changed and why
-   Bug fixes must include a test that would have caught the bug
-   New features must include tests

----------

## Adding an OAuth Provider

This is a great first contribution. You only need to edit one file:

`server/src/config/oauth-providers.ts`

Add your provider to the registry:

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
      getProfile: (data) => ({
        id: String(data.id),
        email: String(data.email),
      }),
    }
  : null,

```

Then add the env vars to `.env.example`. That's it — no route changes needed.

----------

## Running Tests

```bash
# Server tests
cd server && npm test

# SDK tests
cd sdk && npm test

# With coverage
cd server && npm run test:coverage

```

----------

## Questions?

Open a [GitHub Discussion](https://github.com/YugmaGandhi/griffon/discussions).