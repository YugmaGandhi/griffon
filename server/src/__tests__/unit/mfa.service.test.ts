import crypto from 'crypto';
import { TOTP, Secret } from 'otpauth';
import { MfaService } from '../../services/mfa.service';
import { mfaRepository } from '../../repositories/mfa.repository';
import { auditRepository } from '../../repositories/audit.repository';
import { AuthError, NotFoundError } from '../../utils/errors';
import type {
  MfaSetting,
  MfaRecoveryCode,
  OrgMfaPolicy,
} from '../../utils/types';

// ── Mocks ─────────────────────────────────────────────────

jest.mock('../../repositories/mfa.repository');
jest.mock('../../repositories/audit.repository');

jest.mock('../../config/env', () => ({
  env: {
    MFA_ENCRYPTION_KEY:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
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

// ── Test-level crypto helpers ─────────────────────────────
// Mirror the service's encrypt/decrypt with the mocked key so we can build
// realistic MfaSetting fixtures for the "valid code" test paths.

const TEST_KEY =
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function encryptForTest(rawSecret: string): string {
  const key = Buffer.from(TEST_KEY, 'hex');
  const iv = Buffer.alloc(12, 0); // fixed IV — deterministic in tests
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(rawSecret, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${ciphertext.toString('hex')}`;
}

// Generate a valid 6-digit TOTP code for the given base32 secret
function generateTotpCode(base32Secret: string): string {
  const totp = new TOTP({
    issuer: 'Griffon',
    label: 'test',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(base32Secret),
  });
  return totp.generate();
}

// ── Shared test data ──────────────────────────────────────

const KNOWN_BASE32 = new Secret({ size: 20 }).base32; // generated once at module load
const ENCRYPTED_KNOWN = encryptForTest(KNOWN_BASE32);

const userId = '00000000-0000-0000-0000-000000000001';
const orgId = '00000000-0000-0000-0000-000000000002';
const adminId = '00000000-0000-0000-0000-000000000003';
const userEmail = 'user@example.com';

const enabledSetting: MfaSetting = {
  id: 'setting-1',
  userId,
  encryptedSecret: ENCRYPTED_KNOWN,
  isEnabled: true,
  enabledAt: new Date('2024-01-01'),
  createdAt: new Date('2024-01-01'),
};

const disabledSetting: MfaSetting = {
  ...enabledSetting,
  isEnabled: false,
  enabledAt: null,
};

// ── Typed mock refs ───────────────────────────────────────

const mockMfaRepo = mfaRepository as jest.Mocked<typeof mfaRepository>;
const mockAuditRepo = auditRepository as jest.Mocked<typeof auditRepository>;

// ── Suite ─────────────────────────────────────────────────

describe('MfaService', () => {
  let service: MfaService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new MfaService();
    // Default: audit.create is fire-and-forget — always resolve
    mockAuditRepo.create.mockResolvedValue({} as never);
  });

  // ── setupMfa ─────────────────────────────────────────────
  describe('setupMfa()', () => {
    it('should generate a TOTP secret, create setting, generate 8 recovery codes', async () => {
      mockMfaRepo.createSetting.mockResolvedValue(disabledSetting);
      mockMfaRepo.deleteAllRecoveryCodes.mockResolvedValue();
      mockMfaRepo.createRecoveryCodes.mockResolvedValue();

      const result = await service.setupMfa({ userId, userEmail });

      expect(mockMfaRepo.createSetting).toHaveBeenCalledWith(
        userId,
        expect.any(String) // encryptedSecret — non-deterministic
      );
      expect(mockMfaRepo.deleteAllRecoveryCodes).toHaveBeenCalledWith(userId);
      expect(mockMfaRepo.createRecoveryCodes).toHaveBeenCalledWith(
        userId,
        expect.arrayContaining([expect.any(String)])
      );

      // 8 recovery codes returned (raw, not hashed)
      expect(result.recoveryCodes).toHaveLength(8);
      // Each code matches XXXXX-XXXXX format
      result.recoveryCodes.forEach((code) => {
        expect(code).toMatch(/^[0-9A-F]{10}-[0-9A-F]{10}$/);
      });

      // otpauth URI for QR scanning
      expect(result.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
      // base32 secret for manual entry
      expect(result.secret).toBeTruthy();
      expect(typeof result.secret).toBe('string');
    });

    it('should overwrite existing setup — re-enrollment clears old codes', async () => {
      mockMfaRepo.createSetting.mockResolvedValue(disabledSetting);
      mockMfaRepo.deleteAllRecoveryCodes.mockResolvedValue();
      mockMfaRepo.createRecoveryCodes.mockResolvedValue();

      await service.setupMfa({ userId, userEmail });

      // deleteAllRecoveryCodes must run before createRecoveryCodes
      const deleteOrder =
        mockMfaRepo.deleteAllRecoveryCodes.mock.invocationCallOrder[0];
      const createOrder =
        mockMfaRepo.createRecoveryCodes.mock.invocationCallOrder[0];
      expect(deleteOrder).toBeLessThan(createOrder);
    });
  });

  // ── verifySetup ──────────────────────────────────────────
  describe('verifySetup()', () => {
    it('should throw NOT_FOUND when setup was never started', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(null);

      await expect(
        service.verifySetup({ userId, code: '123456' })
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw when MFA is already enabled', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);

      await expect(
        service.verifySetup({ userId, code: '123456' })
      ).rejects.toThrow(AuthError);
    });

    it('should throw MFA_INVALID_CODE for a wrong TOTP code', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(disabledSetting);

      await expect(
        service.verifySetup({ userId, code: '000000' })
      ).rejects.toMatchObject({ code: 'MFA_INVALID_CODE' });
    });

    it('should enable MFA and return SafeMfaSetting on a valid TOTP code', async () => {
      mockMfaRepo.findByUserId
        .mockResolvedValueOnce(disabledSetting) // first call — check state
        .mockResolvedValueOnce(enabledSetting); // second call — re-fetch after enable
      mockMfaRepo.enable.mockResolvedValue();

      const validCode = generateTotpCode(KNOWN_BASE32);
      const result = await service.verifySetup({ userId, code: validCode });

      expect(mockMfaRepo.enable).toHaveBeenCalledWith(userId);
      expect(result.isEnabled).toBe(true);
      // encryptedSecret must NOT appear on the returned object
      expect(
        (result as Record<string, unknown>).encryptedSecret
      ).toBeUndefined();
    });
  });

  // ── verifyLoginCode ───────────────────────────────────────
  describe('verifyLoginCode()', () => {
    it('should throw when MFA is not enabled', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(null);

      await expect(
        service.verifyLoginCode({ userId, code: '123456' })
      ).rejects.toMatchObject({ code: 'MFA_NOT_ENABLED' });
    });

    it('should succeed with a valid TOTP code', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);

      const validCode = generateTotpCode(KNOWN_BASE32);
      await expect(
        service.verifyLoginCode({ userId, code: validCode })
      ).resolves.toBeUndefined();
    });

    it('should succeed with a valid recovery code (single-use — deletes it)', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);
      // TOTP check will fail (wrong format), falls through to recovery code lookup
      const mockRecovery: MfaRecoveryCode = {
        id: 'rc-1',
        userId,
        codeHash: 'hash',
        createdAt: new Date(),
      };
      mockMfaRepo.findRecoveryCode.mockResolvedValue(mockRecovery);
      mockMfaRepo.deleteRecoveryCode.mockResolvedValue();

      // Use a recovery-code shaped string that won't match TOTP format
      await expect(
        service.verifyLoginCode({ userId, code: 'ABCDE12345-FGHIJ67890' })
      ).resolves.toBeUndefined();

      expect(mockMfaRepo.deleteRecoveryCode).toHaveBeenCalledWith('rc-1');
    });

    it('should throw MFA_INVALID_CODE when both TOTP and recovery code fail', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);
      mockMfaRepo.findRecoveryCode.mockResolvedValue(null);

      await expect(
        service.verifyLoginCode({ userId, code: '000000' })
      ).rejects.toMatchObject({ code: 'MFA_INVALID_CODE' });
    });
  });

  // ── disableMfa ───────────────────────────────────────────
  describe('disableMfa()', () => {
    it('should throw when MFA is not enabled', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(null);

      await expect(
        service.disableMfa({ userId, code: '123456' })
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw MFA_INVALID_CODE for wrong TOTP', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);

      await expect(
        service.disableMfa({ userId, code: '000000' })
      ).rejects.toMatchObject({ code: 'MFA_INVALID_CODE' });
    });

    it('should delete the setting on a valid TOTP code', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);
      mockMfaRepo.deleteSetting.mockResolvedValue();

      const validCode = generateTotpCode(KNOWN_BASE32);
      await service.disableMfa({ userId, code: validCode });

      expect(mockMfaRepo.deleteSetting).toHaveBeenCalledWith(userId);
    });
  });

  // ── regenerateRecoveryCodes ───────────────────────────────
  describe('regenerateRecoveryCodes()', () => {
    it('should throw when MFA is not enabled', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(null);

      await expect(
        service.regenerateRecoveryCodes({ userId, code: '123456' })
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw MFA_INVALID_CODE for wrong TOTP', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);

      await expect(
        service.regenerateRecoveryCodes({ userId, code: '000000' })
      ).rejects.toMatchObject({ code: 'MFA_INVALID_CODE' });
    });

    it('should delete old codes and return 8 fresh raw codes on valid TOTP', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);
      mockMfaRepo.deleteAllRecoveryCodes.mockResolvedValue();
      mockMfaRepo.createRecoveryCodes.mockResolvedValue();

      const validCode = generateTotpCode(KNOWN_BASE32);
      const codes = await service.regenerateRecoveryCodes({
        userId,
        code: validCode,
      });

      expect(mockMfaRepo.deleteAllRecoveryCodes).toHaveBeenCalledWith(userId);
      expect(codes).toHaveLength(8);
      codes.forEach((code) => {
        expect(code).toMatch(/^[0-9A-F]{10}-[0-9A-F]{10}$/);
      });
    });
  });

  // ── getStatus ─────────────────────────────────────────────
  describe('getStatus()', () => {
    it('should return disabled when no setting exists', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(null);

      const status = await service.getStatus(userId);

      expect(status).toEqual({
        enabled: false,
        enabledAt: null,
        recoveryCodesRemaining: 0,
      });
    });

    it('should return enabled with recovery code count when MFA is on', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);
      mockMfaRepo.countRecoveryCodes.mockResolvedValue(5);

      const status = await service.getStatus(userId);

      expect(status.enabled).toBe(true);
      expect(status.enabledAt).toEqual(enabledSetting.enabledAt);
      expect(status.recoveryCodesRemaining).toBe(5);
    });
  });

  // ── adminDisableMfa ───────────────────────────────────────
  describe('adminDisableMfa()', () => {
    it('should throw NOT_FOUND when user has no MFA setting', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(null);

      await expect(
        service.adminDisableMfa({ targetUserId: userId, adminId })
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw NOT_FOUND when setup was started but never verified (isEnabled=false)', async () => {
      // A setting row with isEnabled=false does not block login — nothing to disable
      mockMfaRepo.findByUserId.mockResolvedValue(disabledSetting);

      await expect(
        service.adminDisableMfa({ targetUserId: userId, adminId })
      ).rejects.toThrow(NotFoundError);
    });

    it('should delete the setting without requiring a TOTP code', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);
      mockMfaRepo.deleteSetting.mockResolvedValue();

      await service.adminDisableMfa({ targetUserId: userId, adminId });

      expect(mockMfaRepo.deleteSetting).toHaveBeenCalledWith(userId);
    });
  });

  // ── isOrgMfaEnforced ─────────────────────────────────────
  describe('isOrgMfaEnforced()', () => {
    it('should return false when no policy row exists', async () => {
      mockMfaRepo.findOrgPolicy.mockResolvedValue(null);

      const result = await service.isOrgMfaEnforced(orgId);
      expect(result).toBe(false);
    });

    it('should return the policy value when a row exists', async () => {
      const policy: OrgMfaPolicy = {
        id: 'policy-1',
        orgId,
        requireMfa: true,
        enforcedAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockMfaRepo.findOrgPolicy.mockResolvedValue(policy);

      expect(await service.isOrgMfaEnforced(orgId)).toBe(true);
    });
  });

  // ── setOrgMfaPolicy ──────────────────────────────────────
  describe('setOrgMfaPolicy()', () => {
    it('should upsert the policy and return it', async () => {
      const policy: OrgMfaPolicy = {
        id: 'policy-1',
        orgId,
        requireMfa: true,
        enforcedAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockMfaRepo.upsertOrgPolicy.mockResolvedValue(policy);

      const result = await service.setOrgMfaPolicy({
        orgId,
        requireMfa: true,
        actorUserId: adminId,
      });

      expect(mockMfaRepo.upsertOrgPolicy).toHaveBeenCalledWith(orgId, true);
      expect(result).toEqual(policy);
    });
  });

  // ── isMfaEnabled ─────────────────────────────────────────
  describe('isMfaEnabled()', () => {
    it('should return false when no setting', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(null);
      expect(await service.isMfaEnabled(userId)).toBe(false);
    });

    it('should return false when setting exists but isEnabled=false', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(disabledSetting);
      expect(await service.isMfaEnabled(userId)).toBe(false);
    });

    it('should return true when MFA is enrolled and enabled', async () => {
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);
      expect(await service.isMfaEnabled(userId)).toBe(true);
    });
  });

  // ── userSatisfiesOrgMfaPolicy ─────────────────────────────
  describe('userSatisfiesOrgMfaPolicy()', () => {
    it('should return true when org does not enforce MFA', async () => {
      mockMfaRepo.findOrgPolicy.mockResolvedValue(null);

      expect(await service.userSatisfiesOrgMfaPolicy(userId, orgId)).toBe(true);
    });

    it('should return false when org enforces MFA but user has none', async () => {
      const policy: OrgMfaPolicy = {
        id: 'p1',
        orgId,
        requireMfa: true,
        enforcedAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockMfaRepo.findOrgPolicy.mockResolvedValue(policy);
      mockMfaRepo.findByUserId.mockResolvedValue(null);

      expect(await service.userSatisfiesOrgMfaPolicy(userId, orgId)).toBe(
        false
      );
    });

    it('should return true when org enforces MFA and user has MFA enabled', async () => {
      const policy: OrgMfaPolicy = {
        id: 'p1',
        orgId,
        requireMfa: true,
        enforcedAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockMfaRepo.findOrgPolicy.mockResolvedValue(policy);
      mockMfaRepo.findByUserId.mockResolvedValue(enabledSetting);

      expect(await service.userSatisfiesOrgMfaPolicy(userId, orgId)).toBe(true);
    });
  });
});
