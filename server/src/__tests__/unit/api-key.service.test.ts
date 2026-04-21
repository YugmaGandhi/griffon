import { ApiKeyService } from '../../services/api-key.service';
import { apiKeyRepository } from '../../repositories/api-key.repository';
import { userRepository } from '../../repositories/user.repository';
import { auditRepository } from '../../repositories/audit.repository';
import { mfaRepository } from '../../repositories/mfa.repository';
import { mfaService } from '../../services/mfa.service';
import { AuthError, ForbiddenError, NotFoundError } from '../../utils/errors';
import type { ApiKey, SafeUser, MfaSetting } from '../../utils/types';

// ── Mocks ─────────────────────────────────────────────────

jest.mock('../../repositories/api-key.repository');
jest.mock('../../repositories/user.repository');
jest.mock('../../repositories/audit.repository');
jest.mock('../../repositories/mfa.repository');
jest.mock('../../services/mfa.service');

jest.mock('../../config/env', () => ({
  env: {
    MAX_API_KEYS_PER_USER: 10,
    LOG_LEVEL: 'error',
    NODE_ENV: 'test',
  },
}));

jest.mock('../../utils/logger', () => ({
  createLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

// ── Typed mock refs ───────────────────────────────────────

const mockApiKeyRepo = apiKeyRepository as jest.Mocked<typeof apiKeyRepository>;
const mockUserRepo = userRepository as jest.Mocked<typeof userRepository>;
const mockAuditRepo = auditRepository as jest.Mocked<typeof auditRepository>;
const mockMfaRepo = mfaRepository as jest.Mocked<typeof mfaRepository>;
const mockMfaService = mfaService as jest.Mocked<typeof mfaService>;

// ── Fixtures ──────────────────────────────────────────────

const userId = '00000000-0000-0000-0000-000000000001';
const otherUserId = '00000000-0000-0000-0000-000000000002';
const adminId = '00000000-0000-0000-0000-000000000003';
const orgId = '00000000-0000-0000-0000-000000000004';
const keyId = '00000000-0000-0000-0000-000000000005';

const activeKey: ApiKey = {
  id: keyId,
  userId,
  orgId: null,
  name: 'CI Pipeline',
  prefix: 'grf_live_ab',
  keyHash: 'abc123hash',
  permissions: ['read:profile'],
  expiresAt: null,
  lastUsedAt: null,
  revokedAt: null,
  createdAt: new Date('2024-01-01'),
};

const revokedKey: ApiKey = {
  ...activeKey,
  revokedAt: new Date('2024-01-02'),
};

const expiredKey: ApiKey = {
  ...activeKey,
  expiresAt: new Date('2020-01-01'), // past
};

const safeUser: SafeUser = {
  id: userId,
  email: 'user@example.com',
  isVerified: true,
  isDisabled: false,
  isLocked: false,
  failedAttempts: 0,
  lockedUntil: null,
  lastLoginAt: null,
  oauthProvider: null,
  oauthId: null,
  activeOrgId: null,
  createdAt: new Date('2024-01-01'),
  updatedAt: new Date('2024-01-01'),
};

const enabledMfaSetting: MfaSetting = {
  id: 'mfa-1',
  userId,
  encryptedSecret: 'iv:tag:cipher',
  isEnabled: true,
  enabledAt: new Date('2024-01-01'),
  createdAt: new Date('2024-01-01'),
};

// ── Suite ─────────────────────────────────────────────────

describe('ApiKeyService', () => {
  let service: ApiKeyService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new ApiKeyService();
    mockAuditRepo.create.mockResolvedValue({} as never);
    // Default: no MFA enabled
    mockMfaRepo.findByUserId.mockResolvedValue(null);
  });

  // ── createKey ─────────────────────────────────────────────

  describe('createKey()', () => {
    it('should throw when permissions array is empty', async () => {
      await expect(
        service.createKey({ userId, name: 'Key', permissions: [] })
      ).rejects.toThrow(AuthError);
    });

    it('should throw MFA_REQUIRED when user has MFA enabled but no totpCode', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledMfaSetting);

      await expect(
        service.createKey({
          userId,
          name: 'Key',
          permissions: ['read:profile'],
        })
      ).rejects.toMatchObject({ code: 'MFA_REQUIRED' });
    });

    it('should call assertTotpCode when user has MFA and totpCode is provided', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledMfaSetting);
      mockMfaService.assertTotpCode.mockResolvedValue();
      mockApiKeyRepo.countByUserId.mockResolvedValue(0);
      mockApiKeyRepo.create.mockResolvedValue(activeKey);

      await service.createKey({
        userId,
        name: 'Key',
        permissions: ['read:profile'],
        totpCode: '123456',
      });

      expect(mockMfaService.assertTotpCode).toHaveBeenCalledWith(
        userId,
        '123456',
        enabledMfaSetting
      );
    });

    it('should throw API_KEY_LIMIT_REACHED when user is at the limit', async () => {
      mockApiKeyRepo.countByUserId.mockResolvedValue(10);

      await expect(
        service.createKey({
          userId,
          name: 'Key',
          permissions: ['read:profile'],
        })
      ).rejects.toMatchObject({ code: 'API_KEY_LIMIT_REACHED' });
    });

    it('should return plaintext key and SafeApiKey on success', async () => {
      mockApiKeyRepo.countByUserId.mockResolvedValue(0);
      mockApiKeyRepo.create.mockResolvedValue(activeKey);

      const result = await service.createKey({
        userId,
        name: 'CI Pipeline',
        permissions: ['read:profile'],
      });

      // Plaintext has the grf_live_ prefix and correct length
      expect(result.plaintext).toMatch(/^grf_live_[A-Za-z0-9_-]{43}$/);

      // SafeApiKey never includes keyHash
      expect((result.key as Record<string, unknown>).keyHash).toBeUndefined();
      expect(result.key.name).toBe('CI Pipeline');

      // Repository was called with hashed key, not plaintext
      const createCall = mockApiKeyRepo.create.mock.calls[0][0];
      expect(createCall.keyHash).not.toBe(result.plaintext);
      expect(createCall.prefix).toBe(result.plaintext.slice(0, 10));
    });

    it('should write an audit log after creation', async () => {
      mockApiKeyRepo.countByUserId.mockResolvedValue(0);
      mockApiKeyRepo.create.mockResolvedValue(activeKey);

      await service.createKey({
        userId,
        name: 'Key',
        permissions: ['read:profile'],
      });

      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ eventType: 'api_key_created', userId })
      );
    });
  });

  // ── listKeys ──────────────────────────────────────────────

  describe('listKeys()', () => {
    it('should return SafeApiKeys — keyHash stripped', async () => {
      mockApiKeyRepo.findByUserId.mockResolvedValue([activeKey]);

      const keys = await service.listKeys(userId);

      expect(keys).toHaveLength(1);
      expect((keys[0] as Record<string, unknown>).keyHash).toBeUndefined();
      expect(keys[0].name).toBe('CI Pipeline');
    });

    it('should return an empty array when no keys exist', async () => {
      mockApiKeyRepo.findByUserId.mockResolvedValue([]);
      expect(await service.listKeys(userId)).toHaveLength(0);
    });
  });

  // ── getKey ────────────────────────────────────────────────

  describe('getKey()', () => {
    it('should return SafeApiKey for the owner', async () => {
      mockApiKeyRepo.findById.mockResolvedValue(activeKey);

      const key = await service.getKey(keyId, userId);

      expect(key.id).toBe(keyId);
      expect((key as Record<string, unknown>).keyHash).toBeUndefined();
    });

    it('should throw NotFoundError when key does not exist', async () => {
      mockApiKeyRepo.findById.mockResolvedValue(null);

      await expect(service.getKey(keyId, userId)).rejects.toThrow(
        NotFoundError
      );
    });

    it('should throw ForbiddenError when key belongs to another user', async () => {
      mockApiKeyRepo.findById.mockResolvedValue(activeKey); // activeKey.userId === userId

      await expect(service.getKey(keyId, otherUserId)).rejects.toThrow(
        ForbiddenError
      );
    });
  });

  // ── revokeKey ─────────────────────────────────────────────

  describe('revokeKey()', () => {
    it('should throw NotFoundError when key does not exist', async () => {
      mockApiKeyRepo.findById.mockResolvedValue(null);

      await expect(service.revokeKey({ id: keyId, userId })).rejects.toThrow(
        NotFoundError
      );
    });

    it('should throw ForbiddenError when key belongs to another user', async () => {
      mockApiKeyRepo.findById.mockResolvedValue(activeKey);

      await expect(
        service.revokeKey({ id: keyId, userId: otherUserId })
      ).rejects.toThrow(ForbiddenError);
    });

    it('should throw ConflictError when key is already revoked', async () => {
      mockApiKeyRepo.findById.mockResolvedValue(revokedKey);

      await expect(
        service.revokeKey({ id: keyId, userId })
      ).rejects.toMatchObject({ code: 'API_KEY_ALREADY_REVOKED' });
    });

    it('should throw MFA_REQUIRED when user has MFA and no totpCode', async () => {
      mockApiKeyRepo.findById.mockResolvedValue(activeKey);
      mockMfaRepo.findByUserId.mockResolvedValue(enabledMfaSetting);

      await expect(
        service.revokeKey({ id: keyId, userId })
      ).rejects.toMatchObject({ code: 'MFA_REQUIRED' });
    });

    it('should revoke and write audit log on success', async () => {
      mockApiKeyRepo.findById.mockResolvedValue(activeKey);
      mockApiKeyRepo.revoke.mockResolvedValue();

      await service.revokeKey({ id: keyId, userId });

      expect(mockApiKeyRepo.revoke).toHaveBeenCalledWith(keyId);
      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ eventType: 'api_key_revoked', userId })
      );
    });
  });

  // ── authenticateByKey ─────────────────────────────────────

  describe('authenticateByKey()', () => {
    const rawKey = 'grf_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    it('should throw AuthError when key hash is not found', async () => {
      mockApiKeyRepo.findByHash.mockResolvedValue(null);

      await expect(service.authenticateByKey(rawKey)).rejects.toMatchObject({
        code: 'API_KEY_INVALID',
      });
    });

    it('should throw AuthError for a revoked key', async () => {
      mockApiKeyRepo.findByHash.mockResolvedValue(revokedKey);

      await expect(service.authenticateByKey(rawKey)).rejects.toMatchObject({
        code: 'API_KEY_REVOKED',
      });
    });

    it('should throw AuthError for an expired key', async () => {
      mockApiKeyRepo.findByHash.mockResolvedValue(expiredKey);

      await expect(service.authenticateByKey(rawKey)).rejects.toMatchObject({
        code: 'API_KEY_EXPIRED',
      });
    });

    it('should throw AuthError when the key owner no longer exists', async () => {
      mockApiKeyRepo.findByHash.mockResolvedValue(activeKey);
      mockUserRepo.findById.mockResolvedValue(null);

      await expect(service.authenticateByKey(rawKey)).rejects.toMatchObject({
        code: 'API_KEY_INVALID',
      });
    });

    it('should return ApiKeyAuthResult with frozen permissions for a valid key', async () => {
      mockApiKeyRepo.findByHash.mockResolvedValue(activeKey);
      mockUserRepo.findById.mockResolvedValue(safeUser);

      const result = await service.authenticateByKey(rawKey);

      expect(result.keyId).toBe(keyId);
      expect(result.userId).toBe(userId);
      expect(result.email).toBe('user@example.com');
      expect(result.permissions).toEqual(['read:profile']);
      expect(result.orgId).toBeNull();
    });

    it('should pass orgId through when the key is org-scoped', async () => {
      const orgScopedKey: ApiKey = { ...activeKey, orgId };
      mockApiKeyRepo.findByHash.mockResolvedValue(orgScopedKey);
      mockUserRepo.findById.mockResolvedValue(safeUser);

      const result = await service.authenticateByKey(rawKey);

      expect(result.orgId).toBe(orgId);
    });

    it('should look up by SHA-256 hash of the raw key — not plaintext', async () => {
      mockApiKeyRepo.findByHash.mockResolvedValue(activeKey);
      mockUserRepo.findById.mockResolvedValue(safeUser);

      await service.authenticateByKey(rawKey);

      const calledWith = mockApiKeyRepo.findByHash.mock.calls[0][0];
      expect(calledWith).not.toBe(rawKey); // hash ≠ plaintext
      expect(calledWith).toHaveLength(64); // SHA-256 hex = 64 chars
    });
  });

  // ── adminListKeys ─────────────────────────────────────────

  describe('adminListKeys()', () => {
    it('should return SafeApiKeys for any userId without ownership check', async () => {
      mockApiKeyRepo.findByUserId.mockResolvedValue([activeKey]);

      const keys = await service.adminListKeys(otherUserId);

      expect(mockApiKeyRepo.findByUserId).toHaveBeenCalledWith(otherUserId);
      expect(keys).toHaveLength(1);
      expect((keys[0] as Record<string, unknown>).keyHash).toBeUndefined();
    });
  });

  // ── adminRevokeKey ────────────────────────────────────────

  describe('adminRevokeKey()', () => {
    it('should throw NotFoundError when key does not exist', async () => {
      mockApiKeyRepo.findById.mockResolvedValue(null);

      await expect(service.adminRevokeKey({ keyId, adminId })).rejects.toThrow(
        NotFoundError
      );
    });

    it('should throw ConflictError when key is already revoked', async () => {
      mockApiKeyRepo.findById.mockResolvedValue(revokedKey);

      await expect(
        service.adminRevokeKey({ keyId, adminId })
      ).rejects.toMatchObject({ code: 'API_KEY_ALREADY_REVOKED' });
    });

    it('should revoke and write audit log without ownership check', async () => {
      // Key belongs to userId, but adminId is revoking it — should succeed
      mockApiKeyRepo.findById.mockResolvedValue(activeKey);
      mockApiKeyRepo.revoke.mockResolvedValue();

      await service.adminRevokeKey({ keyId, adminId });

      expect(mockApiKeyRepo.revoke).toHaveBeenCalledWith(keyId);
      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'api_key_revoked',
          userId: adminId,
          metadata: expect.objectContaining({ revokedBy: 'admin' }),
        })
      );
    });
  });
});
