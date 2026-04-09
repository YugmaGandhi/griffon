import { AdminService } from '../../services/admin.service';
import { userRepository } from '../../repositories/user.repository';
import { tokenRepository } from '../../repositories/token.repository';
import { auditRepository } from '../../repositories/audit.repository';
import { emailTokenRepository } from '../../repositories/email-token.repository';
import { emailService } from '../../services/email.service';
import { passwordService } from '../../services/password.service';
import { rbacService } from '../../services/rbac.service';
import { redis } from '../../db/redis';
import { ConflictError, NotFoundError } from '../../utils/errors';

jest.mock('../../repositories/user.repository');
jest.mock('../../repositories/token.repository');
jest.mock('../../repositories/audit.repository');
jest.mock('../../repositories/email-token.repository');
jest.mock('../../services/email.service');
jest.mock('../../services/password.service');
jest.mock('../../services/rbac.service');
jest.mock('../../db/redis', () => ({
  redis: { set: jest.fn(), del: jest.fn(), exists: jest.fn() },
}));

const mockUserRepo = userRepository as jest.Mocked<typeof userRepository>;
const mockTokenRepo = tokenRepository as jest.Mocked<typeof tokenRepository>;
const mockAuditRepo = auditRepository as jest.Mocked<typeof auditRepository>;
const mockEmailTokenRepo = emailTokenRepository as jest.Mocked<
  typeof emailTokenRepository
>;
const mockEmailService = emailService as jest.Mocked<typeof emailService>;
const mockPasswordService = passwordService as jest.Mocked<
  typeof passwordService
>;
const mockRbacService = rbacService as jest.Mocked<typeof rbacService>;
const mockRedis = redis as jest.Mocked<typeof redis>;

const adminId = '00000000-0000-0000-0000-000000000001';
const userId = '00000000-0000-0000-0000-000000000002';

const mockSafeUser = {
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
  createdAt: new Date(),
  updatedAt: new Date(),
};

describe('AdminService', () => {
  let service: AdminService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new AdminService();
    mockAuditRepo.create.mockResolvedValue(undefined);
  });

  // ── listUsers ──────────────────────────────────────────
  describe('listUsers()', () => {
    it('should return paginated users', async () => {
      mockUserRepo.findAllPaginated.mockResolvedValue({
        users: [mockSafeUser],
        total: 1,
      });

      const result = await service.listUsers({ page: 1, limit: 20 });

      expect(result.users).toHaveLength(1);
      expect(result.total).toBe(1);
      expect(result.totalPages).toBe(1);
    });

    it('should pass filters to repository', async () => {
      mockUserRepo.findAllPaginated.mockResolvedValue({ users: [], total: 0 });

      await service.listUsers({
        page: 1,
        limit: 20,
        email: 'test',
        isDisabled: true,
      });

      expect(mockUserRepo.findAllPaginated).toHaveBeenCalledWith({
        page: 1,
        limit: 20,
        email: 'test',
        isDisabled: true,
      });
    });
  });

  // ── createUser ─────────────────────────────────────────
  describe('createUser()', () => {
    it('should create a user and send verification email', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null);
      mockPasswordService.hash.mockResolvedValue('hashed');
      mockUserRepo.create.mockResolvedValue(mockSafeUser);
      mockRbacService.assignDefaultRole.mockResolvedValue(undefined);
      mockEmailTokenRepo.create.mockResolvedValue('raw-token');
      mockEmailService.sendVerificationEmail.mockResolvedValue(undefined);

      const result = await service.createUser({
        email: 'user@example.com',
        password: 'password123',
        adminId,
      });

      expect(mockPasswordService.hash).toHaveBeenCalledWith('password123');
      expect(mockRbacService.assignDefaultRole).toHaveBeenCalledWith(userId);
      expect(mockEmailService.sendVerificationEmail).toHaveBeenCalledWith(
        'user@example.com',
        'raw-token'
      );
      expect(result).toEqual(mockSafeUser);
    });

    it('should throw ConflictError if email already exists', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(mockSafeUser as never);

      await expect(
        service.createUser({
          email: 'user@example.com',
          password: 'password123',
          adminId,
        })
      ).rejects.toThrow(ConflictError);
    });
  });

  // ── disableUser ────────────────────────────────────────
  describe('disableUser()', () => {
    it('should disable user, revoke sessions, and add to blocklist', async () => {
      mockUserRepo.findById.mockResolvedValue(mockSafeUser);
      mockUserRepo.disableUser.mockResolvedValue(undefined);
      mockTokenRepo.revokeAllForUser.mockResolvedValue(undefined);
      mockRedis.set.mockResolvedValue('OK');

      await service.disableUser(userId, adminId, '127.0.0.1');

      expect(mockUserRepo.disableUser).toHaveBeenCalledWith(userId);
      expect(mockTokenRepo.revokeAllForUser).toHaveBeenCalledWith(userId);
      expect(mockRedis.set).toHaveBeenCalledWith(
        `blocklist:user:${userId}`,
        '1',
        'EX',
        expect.any(Number)
      );
    });

    it('should throw NotFoundError if user does not exist', async () => {
      mockUserRepo.findById.mockResolvedValue(null);

      await expect(service.disableUser(userId, adminId)).rejects.toThrow(
        NotFoundError
      );
      expect(mockUserRepo.disableUser).not.toHaveBeenCalled();
    });
  });

  // ── enableUser ─────────────────────────────────────────
  describe('enableUser()', () => {
    it('should enable user and remove from blocklist', async () => {
      mockUserRepo.findById.mockResolvedValue(mockSafeUser);
      mockUserRepo.enableUser.mockResolvedValue(undefined);
      mockRedis.del.mockResolvedValue(1);

      await service.enableUser(userId, adminId, '127.0.0.1');

      expect(mockUserRepo.enableUser).toHaveBeenCalledWith(userId);
      expect(mockRedis.del).toHaveBeenCalledWith(`blocklist:user:${userId}`);
    });

    it('should throw NotFoundError if user does not exist', async () => {
      mockUserRepo.findById.mockResolvedValue(null);

      await expect(service.enableUser(userId, adminId)).rejects.toThrow(
        NotFoundError
      );
      expect(mockUserRepo.enableUser).not.toHaveBeenCalled();
    });
  });

  // ── getUserSessions ────────────────────────────────────
  describe('getUserSessions()', () => {
    it('should return sessions for a user', async () => {
      mockUserRepo.findById.mockResolvedValue(mockSafeUser);
      mockTokenRepo.findActiveSessions.mockResolvedValue([]);

      const result = await service.getUserSessions(userId);

      expect(mockTokenRepo.findActiveSessions).toHaveBeenCalledWith(userId);
      expect(result).toEqual([]);
    });

    it('should throw NotFoundError if user does not exist', async () => {
      mockUserRepo.findById.mockResolvedValue(null);

      await expect(service.getUserSessions(userId)).rejects.toThrow(
        NotFoundError
      );
    });
  });
});
