# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x   | Yes       |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them by opening a
[GitHub Security Advisory](https://github.com/YugmaGandhi/vaultauth/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You will receive a response within **48 hours**.

---

## Security Design

VaultAuth is built with these security principles:

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

### Email Security
- Identical responses for unknown emails (enumeration prevention)
- Email tokens stored as SHA-256 hashes
- 24-hour expiry for verification, 1-hour for password reset

---

## Production Checklist

Before deploying VaultAuth to production:

- [ ] Deploy behind HTTPS reverse proxy (Nginx, Caddy, AWS ALB)
- [ ] Set `NODE_ENV=production`
- [ ] Use strong, unique RSA keypair (never reuse dev keys)
- [ ] Restrict `/metrics` to internal network only
- [ ] Enable database SSL (`DATABASE_SSL=true`)
- [ ] Set `CORS_ORIGINS` to your exact frontend domain
- [ ] Store secrets in a secrets manager (not plain env files)
- [ ] Enable database backups
- [ ] Monitor audit logs for suspicious activity
