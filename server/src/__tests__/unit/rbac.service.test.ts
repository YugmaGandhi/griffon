import { RBACService } from '../../services/rbac.service';

// ── Mock dependencies ────────────────────────────────────
jest.mock('../../repositories/role.repository');
jest.mock('../../repositories/user.repository');

import { roleRepository } from '../../repositories/role.repository';
import { userRepository } from '../../repositories/user.repository';

const mockRoleRepo = roleRepository as jest.Mocked<typeof roleRepository>;
const mockUserRepo = userRepository as jest.Mocked<typeof userRepository>;

const rbacService = new RBACService();

const now = new Date();

beforeEach(() => {
  jest.clearAllMocks();
});

describe('RBACService', () => {
  // ── getUserRolesAndPermissions() ────────────────────────
  describe('getUserRolesAndPermissions()', () => {
    it('should return deduplicated roles and permissions', async () => {
      mockRoleRepo.findUserRolesWithPermissions.mockResolvedValue([
        { roleName: 'user', permissionName: 'read:profile' },
        { roleName: 'user', permissionName: 'write:profile' },
        { roleName: 'moderator', permissionName: 'read:users' },
        { roleName: 'moderator', permissionName: 'read:profile' }, // duplicate permission
      ]);

      const result = await rbacService.getUserRolesAndPermissions('user-id');

      expect(result.roles).toEqual(['user', 'moderator']);
      expect(result.permissions).toHaveLength(3);
      expect(result.permissions).toContain('read:profile');
      expect(result.permissions).toContain('write:profile');
      expect(result.permissions).toContain('read:users');
    });

    it('should return empty arrays when user has no roles', async () => {
      mockRoleRepo.findUserRolesWithPermissions.mockResolvedValue([]);

      const result = await rbacService.getUserRolesAndPermissions('user-id');

      expect(result.roles).toEqual([]);
      expect(result.permissions).toEqual([]);
    });

    it('should handle roles with null permissions', async () => {
      mockRoleRepo.findUserRolesWithPermissions.mockResolvedValue([
        { roleName: 'user', permissionName: null },
      ]);

      const result = await rbacService.getUserRolesAndPermissions('user-id');

      expect(result.roles).toEqual(['user']);
      // null permission should not be added
      expect(result.permissions).toEqual([]);
    });
  });

  // ── assignDefaultRole() ─────────────────────────────────
  describe('assignDefaultRole()', () => {
    it('should assign the user role to a new user', async () => {
      mockRoleRepo.findByName.mockResolvedValue({
        id: 'role-uuid',
        name: 'user',
        description: 'Default user role',
        createdAt: now,
      });
      mockRoleRepo.assignToUser.mockResolvedValue(undefined);

      await rbacService.assignDefaultRole('user-id');

      expect(mockRoleRepo.findByName).toHaveBeenCalledWith('user');
      expect(mockRoleRepo.assignToUser).toHaveBeenCalledWith(
        'user-id',
        'role-uuid'
      );
    });

    it('should not throw when default role not found (graceful degradation)', async () => {
      mockRoleRepo.findByName.mockResolvedValue(null as never);

      // Should not throw — just logs an error
      await expect(
        rbacService.assignDefaultRole('user-id')
      ).resolves.toBeUndefined();

      expect(mockRoleRepo.assignToUser).not.toHaveBeenCalled();
    });
  });

  // ── getAllRoles() ───────────────────────────────────────
  describe('getAllRoles()', () => {
    it('should return all roles from repository', async () => {
      const mockRoles = [
        { id: '1', name: 'user', description: 'Default', createdAt: now },
        {
          id: '2',
          name: 'admin',
          description: 'Administrator',
          createdAt: now,
        },
      ];
      mockRoleRepo.findAll.mockResolvedValue(mockRoles);

      const result = await rbacService.getAllRoles();

      expect(result).toEqual(mockRoles);
      expect(mockRoleRepo.findAll).toHaveBeenCalled();
    });
  });

  // ── assignRoleToUser() ──────────────────────────────────
  describe('assignRoleToUser()', () => {
    it('should assign role when user and role exist', async () => {
      mockUserRepo.findById.mockResolvedValue({
        id: 'user-id',
        email: 'test@example.com',
        isVerified: true,
        isDisabled: false,
        isLocked: false,
        failedAttempts: 0,
        lockedUntil: null,
        oauthProvider: null,
        oauthId: null,
        lastLoginAt: null,
        activeOrgId: null,
        createdAt: now,
        updatedAt: now,
      });
      mockRoleRepo.findById.mockResolvedValue({
        id: 'role-id',
        name: 'moderator',
        description: 'Moderator role',
        createdAt: now,
      });
      mockRoleRepo.assignToUser.mockResolvedValue(undefined);

      await rbacService.assignRoleToUser('user-id', 'role-id', 'admin-id');

      expect(mockRoleRepo.assignToUser).toHaveBeenCalledWith(
        'user-id',
        'role-id',
        'admin-id'
      );
    });

    it('should throw when user not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null);

      await expect(
        rbacService.assignRoleToUser('bad-id', 'role-id', 'admin-id')
      ).rejects.toThrow('USER_NOT_FOUND');
    });

    it('should throw when role not found', async () => {
      mockUserRepo.findById.mockResolvedValue({
        id: 'user-id',
        email: 'test@example.com',
        isVerified: true,
        isDisabled: false,
        isLocked: false,
        failedAttempts: 0,
        lockedUntil: null,
        oauthProvider: null,
        oauthId: null,
        lastLoginAt: null,
        activeOrgId: null,
        createdAt: now,
        updatedAt: now,
      });
      mockRoleRepo.findById.mockResolvedValue(null as never);

      await expect(
        rbacService.assignRoleToUser('user-id', 'bad-role', 'admin-id')
      ).rejects.toThrow('ROLE_NOT_FOUND');
    });
  });

  // ── removeRoleFromUser() ────────────────────────────────
  describe('removeRoleFromUser()', () => {
    it('should delegate to repository', async () => {
      mockRoleRepo.removeFromUser.mockResolvedValue(undefined);

      await rbacService.removeRoleFromUser('user-id', 'role-id');

      expect(mockRoleRepo.removeFromUser).toHaveBeenCalledWith(
        'user-id',
        'role-id'
      );
    });
  });

  // ── hasPermission() ─────────────────────────────────────
  describe('hasPermission()', () => {
    it('should return true when user has the required permission', () => {
      expect(
        rbacService.hasPermission(
          ['read:profile', 'write:profile'],
          'read:profile'
        )
      ).toBe(true);
    });

    it('should return false when user lacks the permission', () => {
      expect(rbacService.hasPermission(['read:profile'], 'write:roles')).toBe(
        false
      );
    });

    it('should return false for empty permissions array', () => {
      expect(rbacService.hasPermission([], 'read:profile')).toBe(false);
    });
  });
});
