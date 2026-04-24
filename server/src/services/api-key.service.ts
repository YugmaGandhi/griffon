import crypto from 'crypto';
import { env } from '../config/env';
import { apiKeyRepository } from '../repositories/api-key.repository';
import { userRepository } from '../repositories/user.repository';
import { auditRepository } from '../repositories/audit.repository';
import { mfaRepository } from '../repositories/mfa.repository';
import { mfaService } from './mfa.service';
import {
  AuthError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
} from '../utils/errors';
import { ApiKey, SafeApiKey, toSafeApiKey } from '../utils/types';
import { createLogger } from '../utils/logger';

const log = createLogger('ApiKeyService');

// ── Key generation ────────────────────────────────────────
// Format: grf_live_ (9 chars) + 43 chars base64url = 52 chars total.
// base64url of 32 random bytes = 43 chars (no padding).
function generateRawKey(): string {
  return `grf_live_${crypto.randomBytes(32).toString('base64url')}`;
}

// SHA-256 hex digest — same rationale as refresh tokens (high entropy, no Argon2id needed).
function hashKey(rawKey: string): string {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

// ── MFA gate helper ───────────────────────────────────────
// If the user has MFA enabled, a TOTP code is required for key management actions.
// Recovery codes are intentionally not accepted here — only the live authenticator.
// Pre-fetches the MFA setting once and passes it to assertTotpCode to avoid a double DB call.
async function assertMfaGate(userId: string, totpCode?: string): Promise<void> {
  const setting = await mfaRepository.findByUserId(userId);
  if (!setting?.isEnabled) return;

  if (!totpCode) {
    throw new AuthError(
      'MFA_REQUIRED',
      'This account has MFA enabled. Provide your current TOTP code in the `totpCode` field.',
      403
    );
  }

  await mfaService.assertTotpCode(userId, totpCode, setting);
}

// ── Auth result type ──────────────────────────────────────
// Returned by authenticateByKey so authenticate.ts can build request.user.
// Redis blocklist check and request.user attachment happen in the middleware.
export type ApiKeyAuthResult = {
  keyId: string;
  userId: string;
  email: string;
  permissions: string[];
  orgId: string | null;
};

export class ApiKeyService {
  // ── Create ────────────────────────────────────────────
  // MFA gate → limit check → generate → hash → store → return plaintext once.
  // Plaintext is never stored; loss requires creating a new key.
  async createKey(params: {
    userId: string;
    callerPermissions: string[];
    orgId?: string | null;
    name: string;
    permissions: string[];
    expiresAt?: Date | null;
    totpCode?: string;
    ipAddress?: string;
  }): Promise<{ key: SafeApiKey; plaintext: string }> {
    const {
      userId,
      callerPermissions,
      orgId,
      name,
      permissions,
      expiresAt,
      totpCode,
      ipAddress,
    } = params;

    if (permissions.length === 0) {
      throw new AuthError(
        'PERMISSIONS_REQUIRED',
        'At least one permission must be specified.',
        400
      );
    }

    const callerPermSet = new Set(callerPermissions);
    const disallowed = permissions.filter((p) => !callerPermSet.has(p));
    if (disallowed.length > 0) {
      throw new ForbiddenError(
        'PERMISSION_ESCALATION',
        `You cannot grant permissions you do not hold: ${disallowed.join(', ')}`
      );
    }

    await assertMfaGate(userId, totpCode);

    const rawKey = generateRawKey();
    // 16 chars: "grf_live_" (9) + 7 random base64url chars — enough entropy for audit identification.
    const prefix = rawKey.slice(0, 16);
    const keyHash = hashKey(rawKey);

    const record = await apiKeyRepository.createWithLimitCheck(
      {
        userId,
        orgId: orgId ?? null,
        name,
        prefix,
        keyHash,
        permissions,
        expiresAt: expiresAt ?? null,
      },
      env.MAX_API_KEYS_PER_USER
    );

    void auditRepository
      .create({
        userId,
        eventType: 'api_key_created',
        ipAddress,
        metadata: { keyId: record.id, name, prefix },
      })
      .catch((err: unknown) => {
        log.error(
          { err, eventType: 'api_key_created', userId, keyId: record.id },
          'Failed to write API key creation audit log'
        );
      });

    log.info({ userId, keyId: record.id, name }, 'API key created');

    return { key: toSafeApiKey(record), plaintext: rawKey };
  }

  // ── List ──────────────────────────────────────────────
  // Returns non-revoked keys for the requesting user. keyHash is never included.
  async listKeys(userId: string): Promise<SafeApiKey[]> {
    const keys = await apiKeyRepository.findByUserId(userId);
    return keys.map(toSafeApiKey);
  }

  // ── Get Single ────────────────────────────────────────
  // Ownership check: key must belong to the requesting user.
  async getKey(id: string, userId: string): Promise<SafeApiKey> {
    const key = await this.assertOwnership(id, userId);
    return toSafeApiKey(key);
  }

  // ── Revoke ────────────────────────────────────────────
  // Ownership check first (fail fast if key doesn't exist), then MFA gate.
  async revokeKey(params: {
    id: string;
    userId: string;
    totpCode?: string;
    ipAddress?: string;
  }): Promise<void> {
    const { id, userId, totpCode, ipAddress } = params;

    const key = await this.assertOwnership(id, userId);

    if (key.revokedAt) {
      throw new ConflictError(
        'API_KEY_ALREADY_REVOKED',
        'This API key has already been revoked.'
      );
    }

    await assertMfaGate(userId, totpCode);

    await apiKeyRepository.revoke(id);

    void auditRepository
      .create({
        userId,
        eventType: 'api_key_revoked',
        ipAddress,
        metadata: { keyId: id, name: key.name, prefix: key.prefix },
      })
      .catch((err: unknown) => {
        log.error(
          { err, eventType: 'api_key_revoked', userId, keyId: id },
          'Failed to write API key revocation audit log'
        );
      });

    log.info({ userId, keyId: id }, 'API key revoked');
  }

  // ── Authenticate by raw key ───────────────────────────
  // Called from authenticate.ts when the Authorization header starts with `Bearer grf_live_`.
  // Returns the context needed to populate request.user.
  // Does NOT check the Redis blocklist — authenticate.ts handles that for both paths.
  async authenticateByKey(rawKey: string): Promise<ApiKeyAuthResult> {
    const keyHash = hashKey(rawKey);
    const key = await apiKeyRepository.findByHash(keyHash);

    if (!key) {
      throw new AuthError('API_KEY_INVALID', 'Invalid API key.');
    }

    if (key.revokedAt) {
      throw new AuthError('API_KEY_REVOKED', 'This API key has been revoked.');
    }

    if (key.expiresAt && key.expiresAt < new Date()) {
      throw new AuthError('API_KEY_EXPIRED', 'This API key has expired.');
    }

    const user = await userRepository.findById(key.userId);
    if (!user) {
      throw new AuthError('API_KEY_INVALID', 'Invalid API key.');
    }

    return {
      keyId: key.id,
      userId: key.userId,
      email: user.email,
      permissions: (key.permissions as string[]) ?? [],
      orgId: key.orgId ?? null,
    };
  }

  // ── Admin: list a user's keys ─────────────────────────
  async adminListKeys(userId: string): Promise<SafeApiKey[]> {
    const keys = await apiKeyRepository.findByUserId(userId);
    return keys.map(toSafeApiKey);
  }

  // ── Admin: revoke a target user's key ─────────────────
  // Admin bypasses caller ownership and MFA, but the key must belong to targetUserId.
  async adminRevokeKey(params: {
    keyId: string;
    targetUserId: string;
    adminId: string;
    ipAddress?: string;
  }): Promise<void> {
    const { keyId, targetUserId, adminId, ipAddress } = params;

    const key = await apiKeyRepository.findById(keyId);
    if (!key || key.userId !== targetUserId) {
      throw new NotFoundError('API_KEY_NOT_FOUND', 'API key not found.');
    }

    if (key.revokedAt) {
      throw new ConflictError(
        'API_KEY_ALREADY_REVOKED',
        'This API key has already been revoked.'
      );
    }

    await apiKeyRepository.revoke(keyId);

    void auditRepository
      .create({
        userId: adminId,
        eventType: 'api_key_revoked',
        ipAddress,
        metadata: {
          keyId,
          name: key.name,
          prefix: key.prefix,
          revokedBy: 'admin',
          targetUserId: key.userId,
        },
      })
      .catch((err: unknown) => {
        log.error(
          { err, eventType: 'api_key_revoked', adminId, keyId },
          'Failed to write admin API key revocation audit log'
        );
      });

    log.warn(
      { keyId, adminId, targetUserId: key.userId },
      'API key revoked by admin'
    );
  }

  // ── Private helpers ───────────────────────────────────

  private async assertOwnership(id: string, userId: string): Promise<ApiKey> {
    const key = await apiKeyRepository.findById(id);
    if (!key) {
      throw new NotFoundError('API_KEY_NOT_FOUND', 'API key not found.');
    }
    if (key.userId !== userId) {
      throw new ForbiddenError(
        'API_KEY_ACCESS_DENIED',
        'You do not have access to this API key.'
      );
    }
    return key;
  }
}

export const apiKeyService = new ApiKeyService();
