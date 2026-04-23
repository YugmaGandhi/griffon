# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x   | Yes       |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them by opening a
[GitHub Security Advisory](https://github.com/YugmaGandhi/griffon/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You will receive a response within **48 hours**.

---

## Security Design

Griffon is built with these security principles:

### Password Storage
Passwords are hashed with **Argon2id** (OWASP recommended):
- Memory cost: 64MB
- Time cost: 3 iterations
- Parallelism: 4 threads

### JWT Signing
Tokens are signed with **RS256** (asymmetric RSA):
- 2048-bit key pair
- 15-minute access token expiry
- Private key never leaves the server

### Refresh Tokens
- Cryptographically random (64 bytes)
- Stored as **SHA-256 hash** — never raw value
- **Single-use rotation** — reuse triggers full revocation
- 30-day expiry (configurable)

### Brute Force Protection
- Account lockout after 5 failed attempts
- 15-minute lockout duration
- Redis-backed rate limiting per IP

### Account Disable / Blocklist
- Disabled accounts are blocked at three layers: DB flag, all sessions revoked, Redis blocklist key set
- Every authenticated request checks the blocklist (`blocklist:user:{id}`) — blocked users are rejected even with a valid JWT
- Redis check is fail-open: if Redis is down, the request proceeds (access tokens expire in 15 minutes anyway)
- Blocklist key TTL matches refresh token lifetime (30 days)

### Multi-Factor Authentication (TOTP)
- TOTP secrets generated as 20-byte random values, encoded as base32
- Secrets encrypted at rest with **AES-256-GCM** using `MFA_ENCRYPTION_KEY` — stored as `iv:authTag:ciphertext` (all hex)
- MFA challenge token: 64 random bytes, stored in Redis as SHA-256 hash with 5-minute TTL, consumed atomically via `GETDEL`
- Recovery codes: 8 per user, 80-bit entropy (`XXXXX-XXXXX` format), SHA-256 hashed, single-use enforced by deletion
- TOTP window: ±1 step (30s each) to tolerate clock drift — valid for up to 90 seconds
- Org enforcement: owners can require MFA for all members, enforced at middleware level; super-admins bypass

### API Keys
- Key format: `grf_live_` prefix + 43 cryptographically random base64url characters (52 chars total)
- `grf_live_` prefix makes keys easy to identify in logs, secret scanners, and rotation scripts
- Only the **SHA-256 hash** is stored — the plaintext is returned once at creation and never persisted
- Keys carry explicit permission strings frozen at creation — authenticating with a key never grants more than what was specified
- Optional expiry: keys without an expiry live until explicitly revoked
- **MFA gate**: if the key owner has MFA enrolled, creating or revoking a key requires a valid TOTP code
- Every authenticated request checks the Redis blocklist (`blocklist:user:{id}`) — disabled users are rejected even with a valid key
- `MAX_API_KEYS_PER_USER` (default 10) caps the number of active keys per user to limit blast radius from a compromised account
- Every create and revoke event is written to the audit log with `userId`, key prefix, and (for admin revokes) `revokedBy: admin`

### Webhook Signing
- Every delivery includes `X-Griffon-Signature: sha256=<hmac-sha256-hex>`
- HMAC key is the endpoint's signing secret (32 cryptographically random bytes)
- Secret shown once at registration — encrypted at rest with AES-256-GCM using `WEBHOOK_SECRET_KEY`
- Only HTTPS URLs accepted — HTTP is rejected at registration
- Failed deliveries retry with exponential backoff: 5s → 30s → 2m → 10m → 30m → 2h (max 6 attempts)

### Account Deletion (GDPR)
- Self-service deletion has a 30-day grace period — users can cancel before the purge date
- On purge, the user row is hard-deleted and cascades to all related data (sessions, tokens, org memberships)
- Audit log records deletion event with email before the row is removed
- Admin force-delete is immediate and irreversible — requires `write:users` permission

### Email Security
- Identical responses for unknown emails (enumeration prevention)
- Email tokens stored as SHA-256 hashes
- 24-hour expiry for verification, 1-hour for password reset

---

## Production Checklist

Before deploying Griffon to production:

- [ ] Deploy behind HTTPS reverse proxy (Nginx, Caddy, AWS ALB)
- [ ] Set `NODE_ENV=production`
- [ ] Use strong, unique RSA keypair (never reuse dev keys)
- [ ] Restrict `/metrics` to internal network only
- [ ] Enable database SSL (`DATABASE_SSL=true`)
- [ ] Set `CORS_ORIGINS` to your exact frontend domain
- [ ] Set `WEBHOOK_SECRET_KEY` to a unique 32-byte hex key (`openssl rand -hex 32`)
- [ ] Set `MFA_ENCRYPTION_KEY` to a unique 32-byte hex key (`openssl rand -hex 32`) — must differ from `WEBHOOK_SECRET_KEY`
- [ ] Store secrets in a secrets manager (not plain env files)
- [ ] Enable database backups
- [ ] Monitor audit logs for suspicious activity
