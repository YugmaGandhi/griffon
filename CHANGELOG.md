# Changelog

All notable changes to Griffon are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.3.0] — 2026-04-17

### Added

**TOTP-based Multi-Factor Authentication**

- `POST /auth/mfa/setup` — generates TOTP secret, returns `otpauthUri`, base64 QR code image (`qrCodeDataUrl`), and 8 recovery codes
- `POST /auth/mfa/verify-setup` — confirms enrollment with first TOTP code; activates MFA on the account
- `POST /auth/mfa/verify` — completes two-step login; accepts TOTP code or recovery code, returns full token pair
- `GET /auth/mfa/status` — returns enrollment state and remaining recovery code count
- `DELETE /auth/mfa` — disables MFA (requires valid TOTP code)
- `POST /auth/mfa/recovery-codes` — regenerates all 8 recovery codes (requires valid TOTP code)
- `GET /api/orgs/:orgId/mfa-policy` — org owners and admins can read the MFA enforcement policy
- `PUT /api/orgs/:orgId/mfa-policy` — org owners can enable/disable MFA enforcement for all members
- `DELETE /api/admin/users/:id/mfa` — admins can force-disable MFA for a user (support recovery flow)
- `requireMfaIfEnforced()` middleware — blocks org-scoped endpoints for members without MFA when enforcement is on; super-admins bypass
- `POST /auth/login` now returns `{ mfaRequired: true, mfaToken }` when MFA is enrolled instead of tokens
- OAuth login (`oauthLogin`) also gates on MFA — same two-step flow applies

**Security**

- TOTP secrets encrypted at rest with AES-256-GCM (`MFA_ENCRYPTION_KEY`)
- MFA challenge token stored in Redis as SHA-256 hash, consumed atomically via `GETDEL` (prevents single-use race condition)
- Recovery codes: 80-bit entropy, SHA-256 hashed, normalized before hashing (dash-insensitive matching)
- `env.ts` now rejects `MFA_ENCRYPTION_KEY === WEBHOOK_SECRET_KEY` in production

**Other**

- `mfa_recovery_codes.user_id` index added — avoids full table scans on recovery code lookup
- Bruno collection: 9 new request files covering all MFA and org policy endpoints
- `login.bru` updated to auto-save `mfaToken` and clear stale tokens on MFA challenge
- `qrcode` package added for server-side QR code generation

### Changed

- `POST /auth/login` response shape — added `mfaRequired` field (always present, `false` for non-MFA logins)

---

## [0.2.0] — 2025

### Added

- Webhook events — HTTPS callbacks with HMAC-SHA256 signing and exponential backoff retry
- Admin user management API — create, update, disable, enable, force-delete users
- Account deletion — GDPR-compliant self-service with 30-day grace period
- Prometheus metrics endpoint (`/metrics`)
- JavaScript SDK (`@griffon/js`)

---

## [0.1.0] — 2025

### Added

- Email + password registration and login with Argon2id hashing
- OAuth2 — Google, GitHub, Microsoft
- JWT with RS256 signing and refresh token rotation
- RBAC — roles and permissions embedded in tokens
- Multi-organization support with org-scoped roles
- Session management — list and revoke sessions
- Email verification and password reset flows
- Redis-backed rate limiting and brute force protection
- Audit logging
