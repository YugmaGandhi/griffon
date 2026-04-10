import { DeletionService } from '../../services/deletion.service';
import { deletionRepository } from '../../repositories/deletion.repository';
import { userRepository } from '../../repositories/user.repository';
import { auditRepository } from '../../repositories/audit.repository';
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
} from '../../utils/errors';
import { DeletionRequest } from '../../utils/types';

jest.mock('../../repositories/deletion.repository');
jest.mock('../../repositories/user.repository');
jest.mock('../../repositories/audit.repository');

const mockDeletionRepo = deletionRepository as jest.Mocked<
  typeof deletionRepository
>;
const mockUserRepo = userRepository as jest.Mocked<typeof userRepository>;
const mockAuditRepo = auditRepository as jest.Mocked<typeof auditRepository>;

const userId = '00000000-0000-0000-0000-000000000001';
const adminId = '00000000-0000-0000-0000-000000000002';

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

const mockRequest: DeletionRequest = {
  id: 'req-001',
  userId,
  requestedAt: new Date(),
  scheduledPurgeAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  status: 'pending',
  cancelledAt: null,
  forcedByAdmin: false,
};

describe('DeletionService', () => {
  let service: DeletionService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new DeletionService();
    mockAuditRepo.create.mockResolvedValue(undefined);
  });

  // ── requestDeletion ────────────────────────────────────
  describe('requestDeletion()', () => {
    it('should create a deletion request and return scheduledPurgeAt', async () => {
      mockDeletionRepo.findPendingByUserId.mockResolvedValue(null);
      mockDeletionRepo.create.mockResolvedValue(mockRequest);

      const result = await service.requestDeletion({ userId });

      expect(mockDeletionRepo.create).toHaveBeenCalledWith(userId);
      expect(result.scheduledPurgeAt).toEqual(mockRequest.scheduledPurgeAt);
      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ eventType: 'account_deletion_requested' })
      );
    });

    it('should throw ConflictError if a pending request already exists', async () => {
      mockDeletionRepo.findPendingByUserId.mockResolvedValue(mockRequest);

      await expect(service.requestDeletion({ userId })).rejects.toThrow(
        ConflictError
      );
      expect(mockDeletionRepo.create).not.toHaveBeenCalled();
    });
  });

  // ── cancelDeletion ─────────────────────────────────────
  describe('cancelDeletion()', () => {
    it('should cancel a pending deletion request', async () => {
      mockDeletionRepo.findPendingByUserId.mockResolvedValue(mockRequest);
      mockDeletionRepo.cancel.mockResolvedValue(undefined);

      await service.cancelDeletion({ userId });

      expect(mockDeletionRepo.cancel).toHaveBeenCalledWith(mockRequest.id);
      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ eventType: 'account_deletion_cancelled' })
      );
    });

    it('should throw NotFoundError if no pending request exists', async () => {
      mockDeletionRepo.findPendingByUserId.mockResolvedValue(null);

      await expect(service.cancelDeletion({ userId })).rejects.toThrow(
        NotFoundError
      );
      expect(mockDeletionRepo.cancel).not.toHaveBeenCalled();
    });
  });

  // ── forceDelete ────────────────────────────────────────
  describe('forceDelete()', () => {
    it('should delete user and write audit log', async () => {
      mockUserRepo.findById.mockResolvedValue(mockSafeUser);
      mockUserRepo.deleteUser.mockResolvedValue(undefined);

      await service.forceDelete({ userId, adminId });

      expect(mockUserRepo.deleteUser).toHaveBeenCalledWith(userId);
      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'account_deleted',
          userId: adminId,
          metadata: expect.objectContaining({ forced: true }),
        })
      );
    });

    it('should throw ForbiddenError if admin tries to delete themselves', async () => {
      await expect(
        service.forceDelete({ userId: adminId, adminId })
      ).rejects.toThrow(ForbiddenError);
      expect(mockUserRepo.deleteUser).not.toHaveBeenCalled();
    });

    it('should throw NotFoundError if user does not exist', async () => {
      mockUserRepo.findById.mockResolvedValue(null);

      await expect(service.forceDelete({ userId, adminId })).rejects.toThrow(
        NotFoundError
      );
      expect(mockUserRepo.deleteUser).not.toHaveBeenCalled();
    });
  });

  // ── purgeExpired ───────────────────────────────────────
  describe('purgeExpired()', () => {
    it('should purge due deletion requests and return count', async () => {
      const overdueRequest = { ...mockRequest, scheduledPurgeAt: new Date(0) };
      mockDeletionRepo.findDue.mockResolvedValue([overdueRequest]);
      mockUserRepo.findById.mockResolvedValue(mockSafeUser);
      mockDeletionRepo.markCompleted.mockResolvedValue(undefined);
      mockUserRepo.deleteUser.mockResolvedValue(undefined);

      const purged = await service.purgeExpired();

      expect(purged).toBe(1);
      expect(mockDeletionRepo.markCompleted).toHaveBeenCalledWith(
        overdueRequest.id
      );
      expect(mockUserRepo.deleteUser).toHaveBeenCalledWith(userId);
      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ eventType: 'account_deleted' })
      );
    });

    it('should skip requests with null userId', async () => {
      const nullUserRequest = { ...mockRequest, userId: null };
      mockDeletionRepo.findDue.mockResolvedValue([nullUserRequest]);

      const purged = await service.purgeExpired();

      expect(purged).toBe(0);
      expect(mockUserRepo.deleteUser).not.toHaveBeenCalled();
    });

    it('should continue purging remaining accounts if one fails', async () => {
      const req1 = { ...mockRequest, id: 'req-001', userId };
      const req2 = {
        ...mockRequest,
        id: 'req-002',
        userId: '00000000-0000-0000-0000-000000000099',
      };
      mockDeletionRepo.findDue.mockResolvedValue([req1, req2]);
      mockUserRepo.findById.mockResolvedValue(mockSafeUser);
      mockDeletionRepo.markCompleted.mockResolvedValue(undefined);
      mockUserRepo.deleteUser
        .mockRejectedValueOnce(new Error('DB error'))
        .mockResolvedValueOnce(undefined);

      const purged = await service.purgeExpired();

      expect(purged).toBe(1);
    });

    it('should return 0 when no accounts are due', async () => {
      mockDeletionRepo.findDue.mockResolvedValue([]);

      const purged = await service.purgeExpired();

      expect(purged).toBe(0);
    });
  });
});
