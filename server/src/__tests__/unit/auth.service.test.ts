import { AuthService } from '../../services/auth.service';
import { AuthError, ConflictError, ForbiddenError } from '../../utils/errors';

// ── Mock all dependencies ────────────────────────────────
jest.mock('../../repositories/user.repository');
jest.mock('../../repositories/audit.repository');
jest.mock('../../repositories/token.repository');
jest.mock('../../repositories/email-token.repository');
jest.mock('../../services/password.service');
jest.mock('../../services/token.service');
jest.mock('../../services/email.service');
jest.mock('../../services/rbac.service');
jest.mock('../../utils/metrics', () => ({
  authEventsTotal: { inc: jest.fn() },
}));

import { userRepository } from '../../repositories/user.repository';
import { auditRepository } from '../../repositories/audit.repository';
import { tokenRepository } from '../../repositories/token.repository';
import { emailTokenRepository } from '../../repositories/email-token.repository';
import { passwordService } from '../../services/password.service';
import { tokenService } from '../../services/token.service';
import { emailService } from '../../services/email.service';
import { rbacService } from '../../services/rbac.service';

const authService = new AuthService();

// Typed mocks for convenience
const mockUserRepo = userRepository as jest.Mocked<typeof userRepository>;
const mockAuditRepo = auditRepository as jest.Mocked<typeof auditRepository>;
const mockTokenRepo = tokenRepository as jest.Mocked<typeof tokenRepository>;
const mockEmailTokenRepo = emailTokenRepository as jest.Mocked<
  typeof emailTokenRepository
>;
const mockPasswordService = passwordService as jest.Mocked<
  typeof passwordService
>;
const mockTokenService = tokenService as jest.Mocked<typeof tokenService>;
const mockEmailService = emailService as jest.Mocked<typeof emailService>;
const mockRbacService = rbacService as jest.Mocked<typeof rbacService>;

// ── Shared fixtures ──────────────────────────────────────
const now = new Date();

const mockSafeUser = {
  id: '550e8400-e29b-41d4-a716-446655440000',
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
};

const mockFullUser = {
  ...mockSafeUser,
  passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$fakehash',
};

beforeEach(() => {
  jest.clearAllMocks();

  // Default happy-path stubs
  mockAuditRepo.create.mockResolvedValue(undefined);
  mockRbacService.assignDefaultRole.mockResolvedValue(undefined);
  mockRbacService.getUserRolesAndPermissions.mockResolvedValue({
    roles: ['user'],
    permissions: ['read:profile'],
  });
  mockTokenService.generateRefreshToken.mockReturnValue('mock-refresh-token');
  mockTokenService.hashRefreshToken.mockReturnValue('mock-hash');
  mockTokenService.getRefreshTokenExpiry.mockReturnValue(
    new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
  );
  mockTokenService.generateAccessToken.mockResolvedValue('mock-access-token');
  mockTokenRepo.create.mockResolvedValue({ id: 'mock-session-id' } as never);
});

describe('AuthService', () => {
  // ── register() ──────────────────────────────────────────
  describe('register()', () => {
    it('should register a new user successfully', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null);
      mockPasswordService.hash.mockResolvedValue('hashed-password');
      mockUserRepo.create.mockResolvedValue(mockSafeUser);
      mockEmailTokenRepo.create.mockResolvedValue('mock-email-token');
      mockEmailService.sendVerificationEmail.mockResolvedValue(undefined);

      const result = await authService.register({
        email: 'test@example.com',
        password: 'StrongPass123!',
        ipAddress: '127.0.0.1',
      });

      expect(result.user.email).toBe('test@example.com');
      expect(result.message).toContain('check your email');
      expect(mockPasswordService.hash).toHaveBeenCalledWith('StrongPass123!');
      expect(mockUserRepo.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        passwordHash: 'hashed-password',
      });
      expect(mockRbacService.assignDefaultRole).toHaveBeenCalledWith(
        mockSafeUser.id
      );
    });

    it('should normalize email to lowercase', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null);
      mockPasswordService.hash.mockResolvedValue('hashed-password');
      mockUserRepo.create.mockResolvedValue(mockSafeUser);
      mockEmailTokenRepo.create.mockResolvedValue('mock-email-token');
      mockEmailService.sendVerificationEmail.mockResolvedValue(undefined);

      await authService.register({
        email: 'TEST@EXAMPLE.COM',
        password: 'StrongPass123!',
      });

      expect(mockUserRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ email: 'test@example.com' })
      );
    });

    it('should throw ConflictError when email already exists', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(mockFullUser);

      await expect(
        authService.register({
          email: 'test@example.com',
          password: 'StrongPass123!',
        })
      ).rejects.toThrow(ConflictError);
    });

    it('should fire audit log without blocking', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null);
      mockPasswordService.hash.mockResolvedValue('hashed-password');
      mockUserRepo.create.mockResolvedValue(mockSafeUser);
      mockEmailTokenRepo.create.mockResolvedValue('mock-email-token');
      mockEmailService.sendVerificationEmail.mockResolvedValue(undefined);

      await authService.register({
        email: 'test@example.com',
        password: 'StrongPass123!',
        ipAddress: '10.0.0.1',
        userAgent: 'Jest',
      });

      // Audit log is fire-and-forget — but still called
      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockSafeUser.id,
          eventType: 'user_registered',
          ipAddress: '10.0.0.1',
        })
      );
    });

    it('should never return passwordHash', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null);
      mockPasswordService.hash.mockResolvedValue('hashed-password');
      mockUserRepo.create.mockResolvedValue(mockSafeUser);
      mockEmailTokenRepo.create.mockResolvedValue('mock-email-token');
      mockEmailService.sendVerificationEmail.mockResolvedValue(undefined);

      const result = await authService.register({
        email: 'test@example.com',
        password: 'StrongPass123!',
      });

      expect(result.user).not.toHaveProperty('passwordHash');
    });
  });

  // ── login() ─────────────────────────────────────────────
  describe('login()', () => {
    it('should login successfully with valid credentials', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(mockFullUser);
      mockPasswordService.verify.mockResolvedValue(true);
      mockUserRepo.resetFailedAttempts.mockResolvedValue(undefined);
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined);

      const result = await authService.login({
        email: 'test@example.com',
        password: 'StrongPass123!',
      });

      expect(result.accessToken).toBe('mock-access-token');
      expect(result.refreshToken).toBe('mock-refresh-token');
      expect(result.expiresIn).toBe(900);
      expect(result.user.email).toBe('test@example.com');
      expect(result.user.roles).toEqual(['user']);
      expect(result.user.permissions).toEqual(['read:profile']);
      expect(result.user).not.toHaveProperty('passwordHash');
    });

    it('should throw AuthError when user not found', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null);

      await expect(
        authService.login({
          email: 'nonexistent@example.com',
          password: 'whatever',
        })
      ).rejects.toThrow(AuthError);
    });

    it('should throw AuthError when account is locked and lockout not expired', async () => {
      const lockedUser = {
        ...mockFullUser,
        isLocked: true,
        lockedUntil: new Date(Date.now() + 60000), // 1 min in future
      };
      mockUserRepo.findByEmail.mockResolvedValue(lockedUser);

      await expect(
        authService.login({
          email: 'test@example.com',
          password: 'StrongPass123!',
        })
      ).rejects.toThrow('Account temporarily locked');
    });

    it('should reset lockout when lockout period has expired', async () => {
      const expiredLockUser = {
        ...mockFullUser,
        isLocked: true,
        lockedUntil: new Date(Date.now() - 60000), // 1 min in past
      };
      mockUserRepo.findByEmail.mockResolvedValue(expiredLockUser);
      mockPasswordService.verify.mockResolvedValue(true);
      mockUserRepo.resetFailedAttempts.mockResolvedValue(undefined);
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined);

      const result = await authService.login({
        email: 'test@example.com',
        password: 'StrongPass123!',
      });

      // Should reset failed attempts because lockout expired
      expect(mockUserRepo.resetFailedAttempts).toHaveBeenCalledWith(
        mockFullUser.id
      );
      expect(result.accessToken).toBe('mock-access-token');
    });

    it('should throw ForbiddenError when account is disabled by admin', async () => {
      const disabledUser = { ...mockFullUser, isDisabled: true };
      mockUserRepo.findByEmail.mockResolvedValue(disabledUser);

      await expect(
        authService.login({
          email: 'test@example.com',
          password: 'StrongPass123!',
        })
      ).rejects.toThrow(ForbiddenError);
    });

    it('should throw ForbiddenError when email not verified', async () => {
      const unverifiedUser = { ...mockFullUser, isVerified: false };
      mockUserRepo.findByEmail.mockResolvedValue(unverifiedUser);

      await expect(
        authService.login({
          email: 'test@example.com',
          password: 'StrongPass123!',
        })
      ).rejects.toThrow(ForbiddenError);
    });

    it('should increment failed attempts on wrong password', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(mockFullUser);
      mockPasswordService.verify.mockResolvedValue(false);
      mockUserRepo.incrementFailedAttempts.mockResolvedValue(undefined);

      await expect(
        authService.login({
          email: 'test@example.com',
          password: 'WrongPass!',
        })
      ).rejects.toThrow(AuthError);

      expect(mockUserRepo.incrementFailedAttempts).toHaveBeenCalledWith(
        mockFullUser.id
      );
    });

    it('should lock account after 5 failed attempts', async () => {
      const almostLockedUser = { ...mockFullUser, failedAttempts: 4 };
      mockUserRepo.findByEmail.mockResolvedValue(almostLockedUser);
      mockPasswordService.verify.mockResolvedValue(false);
      mockUserRepo.incrementFailedAttempts.mockResolvedValue(undefined);
      mockUserRepo.lockAccount.mockResolvedValue(undefined);

      await expect(
        authService.login({
          email: 'test@example.com',
          password: 'WrongPass!',
        })
      ).rejects.toThrow('Account temporarily locked');

      expect(mockUserRepo.lockAccount).toHaveBeenCalledWith(
        mockFullUser.id,
        expect.any(Date)
      );
    });

    it('should store refresh token hash in repository', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(mockFullUser);
      mockPasswordService.verify.mockResolvedValue(true);
      mockUserRepo.resetFailedAttempts.mockResolvedValue(undefined);
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined);

      await authService.login({
        email: 'test@example.com',
        password: 'StrongPass123!',
        ipAddress: '127.0.0.1',
        userAgent: 'Jest',
      });

      expect(mockTokenRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockFullUser.id,
          tokenHash: 'mock-hash',
          deviceInfo: 'Jest',
          ipAddress: '127.0.0.1',
        })
      );
    });
  });

  // ── logout() ────────────────────────────────────────────
  describe('logout()', () => {
    it('should revoke refresh token on logout', async () => {
      mockTokenRepo.findByHash.mockResolvedValue({
        id: 'token-id',
        userId: mockSafeUser.id,
        tokenHash: 'mock-hash',
        revokedAt: null,
        expiresAt: new Date(Date.now() + 86400000),
        createdAt: now,
        deviceInfo: null,
        ipAddress: null,
      });
      mockTokenRepo.revoke.mockResolvedValue(undefined as never);

      await authService.logout({
        refreshToken: 'mock-refresh-token',
        userId: mockSafeUser.id,
      });

      expect(mockTokenService.hashRefreshToken).toHaveBeenCalledWith(
        'mock-refresh-token'
      );
      expect(mockTokenRepo.revoke).toHaveBeenCalledWith('token-id');
    });

    it('should not throw when token not found (already revoked)', async () => {
      mockTokenRepo.findByHash.mockResolvedValue(null as never);

      await expect(
        authService.logout({
          refreshToken: 'unknown-token',
          userId: mockSafeUser.id,
        })
      ).resolves.toBeUndefined();
    });

    it('should write audit log on logout', async () => {
      mockTokenRepo.findByHash.mockResolvedValue(null as never);

      await authService.logout({
        refreshToken: 'mock-refresh-token',
        userId: mockSafeUser.id,
        ipAddress: '10.0.0.1',
      });

      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockSafeUser.id,
          eventType: 'user_logout',
          ipAddress: '10.0.0.1',
        })
      );
    });
  });

  // ── refreshTokens() ────────────────────────────────────
  describe('refreshTokens()', () => {
    const mockStoredToken = {
      id: 'token-id',
      userId: mockSafeUser.id,
      tokenHash: 'mock-hash',
      revokedAt: null,
      expiresAt: new Date(Date.now() + 86400000),
      createdAt: now,
      deviceInfo: null,
      ipAddress: null,
    };

    it('should rotate tokens successfully', async () => {
      mockTokenRepo.findByHash.mockResolvedValue(mockStoredToken);
      mockUserRepo.findById.mockResolvedValue(mockSafeUser);
      mockTokenRepo.revoke.mockResolvedValue(undefined as never);

      const result = await authService.refreshTokens({
        refreshToken: 'old-refresh-token',
      });

      expect(result.accessToken).toBe('mock-access-token');
      expect(result.refreshToken).toBe('mock-refresh-token');
      expect(result.expiresIn).toBe(900);
      // Old token should be revoked (single-use)
      expect(mockTokenRepo.revoke).toHaveBeenCalledWith('token-id');
      // New token should be stored
      expect(mockTokenRepo.create).toHaveBeenCalled();
    });

    it('should throw AuthError when token not found', async () => {
      mockTokenRepo.findByHash.mockResolvedValue(null as never);

      await expect(
        authService.refreshTokens({ refreshToken: 'bad-token' })
      ).rejects.toThrow(AuthError);
    });

    it('should throw AuthError when token expired', async () => {
      const expiredToken = {
        ...mockStoredToken,
        expiresAt: new Date(Date.now() - 1000), // expired
      };
      mockTokenRepo.findByHash.mockResolvedValue(expiredToken);

      await expect(
        authService.refreshTokens({ refreshToken: 'expired-token' })
      ).rejects.toThrow('Your session has expired');
    });

    it('should throw AuthError when user not found', async () => {
      mockTokenRepo.findByHash.mockResolvedValue(mockStoredToken);
      mockTokenRepo.revoke.mockResolvedValue(undefined as never);
      mockUserRepo.findById.mockResolvedValue(null);

      await expect(
        authService.refreshTokens({ refreshToken: 'some-token' })
      ).rejects.toThrow(AuthError);
    });
  });

  // ── getMe() ─────────────────────────────────────────────
  describe('getMe()', () => {
    it('should return user with roles and permissions', async () => {
      mockUserRepo.findById.mockResolvedValue(mockSafeUser);

      const result = await authService.getMe(mockSafeUser.id);

      expect(result.email).toBe('test@example.com');
      expect(result.roles).toEqual(['user']);
      expect(result.permissions).toEqual(['read:profile']);
      expect(result).not.toHaveProperty('passwordHash');
    });

    it('should throw AuthError when user not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null);

      await expect(authService.getMe('nonexistent-id')).rejects.toThrow(
        AuthError
      );
    });
  });

  // ── verifyEmail() ───────────────────────────────────────
  describe('verifyEmail()', () => {
    it('should verify email with valid token', async () => {
      mockEmailTokenRepo.findValid.mockResolvedValue({
        id: 'token-id',
        userId: mockSafeUser.id,
        tokenHash: 'hash',
        type: 'email_verification',
        expiresAt: new Date(Date.now() + 86400000),
        usedAt: null,
        createdAt: now,
      });
      mockUserRepo.markEmailVerified.mockResolvedValue(undefined);
      mockEmailTokenRepo.markUsed.mockResolvedValue(undefined);

      await authService.verifyEmail('valid-token');

      expect(mockUserRepo.markEmailVerified).toHaveBeenCalledWith(
        mockSafeUser.id
      );
      expect(mockEmailTokenRepo.markUsed).toHaveBeenCalledWith('token-id');
    });

    it('should throw AuthError for invalid or used token', async () => {
      mockEmailTokenRepo.findValid.mockResolvedValue(null);

      await expect(authService.verifyEmail('invalid-token')).rejects.toThrow(
        AuthError
      );
    });

    it('should write audit log on successful verification', async () => {
      mockEmailTokenRepo.findValid.mockResolvedValue({
        id: 'token-id',
        userId: mockSafeUser.id,
        tokenHash: 'hash',
        type: 'email_verification',
        expiresAt: new Date(Date.now() + 86400000),
        usedAt: null,
        createdAt: now,
      });
      mockUserRepo.markEmailVerified.mockResolvedValue(undefined);
      mockEmailTokenRepo.markUsed.mockResolvedValue(undefined);

      await authService.verifyEmail('valid-token');

      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockSafeUser.id,
          eventType: 'email_verified',
        })
      );
    });
  });

  // ── forgotPassword() ────────────────────────────────────
  describe('forgotPassword()', () => {
    it('should send reset email when user exists', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(mockFullUser);
      mockEmailTokenRepo.create.mockResolvedValue('reset-token');
      mockEmailService.sendPasswordResetEmail.mockResolvedValue(undefined);

      await authService.forgotPassword('test@example.com', '127.0.0.1');

      expect(mockEmailTokenRepo.create).toHaveBeenCalledWith(
        mockFullUser.id,
        'password_reset',
        1
      );
      expect(mockEmailService.sendPasswordResetEmail).toHaveBeenCalledWith(
        'test@example.com',
        'reset-token'
      );
    });

    it('should not throw when user does not exist (prevents enumeration)', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null);

      await expect(
        authService.forgotPassword('nobody@example.com')
      ).resolves.toBeUndefined();

      // Should NOT attempt to send email
      expect(mockEmailService.sendPasswordResetEmail).not.toHaveBeenCalled();
    });

    it('should write audit log when user exists', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(mockFullUser);
      mockEmailTokenRepo.create.mockResolvedValue('reset-token');
      mockEmailService.sendPasswordResetEmail.mockResolvedValue(undefined);

      await authService.forgotPassword('test@example.com', '10.0.0.1');

      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockFullUser.id,
          eventType: 'password_reset_requested',
        })
      );
    });
  });

  // ── resetPassword() ─────────────────────────────────────
  describe('resetPassword()', () => {
    it('should reset password with valid token', async () => {
      mockEmailTokenRepo.findValid.mockResolvedValue({
        id: 'token-id',
        userId: mockSafeUser.id,
        tokenHash: 'hash',
        type: 'password_reset',
        expiresAt: new Date(Date.now() + 3600000),
        usedAt: null,
        createdAt: now,
      });
      mockPasswordService.hash.mockResolvedValue('new-hashed-password');
      mockUserRepo.updatePassword.mockResolvedValue(undefined);
      mockEmailTokenRepo.markUsed.mockResolvedValue(undefined);
      mockTokenRepo.revokeAllForUser.mockResolvedValue(undefined as never);

      await authService.resetPassword('valid-token', 'NewStrongPass123!');

      expect(mockPasswordService.hash).toHaveBeenCalledWith(
        'NewStrongPass123!'
      );
      expect(mockUserRepo.updatePassword).toHaveBeenCalledWith(
        mockSafeUser.id,
        'new-hashed-password'
      );
      expect(mockEmailTokenRepo.markUsed).toHaveBeenCalledWith('token-id');
    });

    it('should revoke all refresh tokens after password reset', async () => {
      mockEmailTokenRepo.findValid.mockResolvedValue({
        id: 'token-id',
        userId: mockSafeUser.id,
        tokenHash: 'hash',
        type: 'password_reset',
        expiresAt: new Date(Date.now() + 3600000),
        usedAt: null,
        createdAt: now,
      });
      mockPasswordService.hash.mockResolvedValue('new-hashed-password');
      mockUserRepo.updatePassword.mockResolvedValue(undefined);
      mockEmailTokenRepo.markUsed.mockResolvedValue(undefined);
      mockTokenRepo.revokeAllForUser.mockResolvedValue(undefined as never);

      await authService.resetPassword('valid-token', 'NewStrongPass123!');

      // All sessions must be invalidated after password change
      expect(mockTokenRepo.revokeAllForUser).toHaveBeenCalledWith(
        mockSafeUser.id
      );
    });

    it('should throw AuthError for invalid or used token', async () => {
      mockEmailTokenRepo.findValid.mockResolvedValue(null);

      await expect(
        authService.resetPassword('invalid-token', 'NewPass123!')
      ).rejects.toThrow(AuthError);
    });
  });

  // ── oauthLogin() ────────────────────────────────────────
  describe('oauthLogin()', () => {
    const mockProfile = { id: 'google-123', email: 'oauth@example.com' };

    it('should login existing OAuth user', async () => {
      mockUserRepo.findByOAuthId.mockResolvedValue(mockSafeUser);
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined);

      const result = await authService.oauthLogin({
        profile: mockProfile,
        providerName: 'google',
      });

      expect(result.accessToken).toBe('mock-access-token');
      expect(result.refreshToken).toBe('mock-refresh-token');
      expect(result.user.email).toBe(mockSafeUser.email);
    });

    it('should link OAuth to existing email account', async () => {
      mockUserRepo.findByOAuthId.mockResolvedValue(null);
      mockUserRepo.findByEmail.mockResolvedValue(mockFullUser);
      mockUserRepo.linkOAuth.mockResolvedValue(undefined);
      mockUserRepo.findById.mockResolvedValue(mockSafeUser);
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined);

      const result = await authService.oauthLogin({
        profile: mockProfile,
        providerName: 'google',
      });

      expect(mockUserRepo.linkOAuth).toHaveBeenCalledWith(
        mockFullUser.id,
        'google',
        'google-123'
      );
      expect(result.accessToken).toBe('mock-access-token');
    });

    it('should create new user for new OAuth login', async () => {
      const newOAuthUser = {
        ...mockSafeUser,
        email: 'oauth@example.com',
        oauthProvider: 'google',
        oauthId: 'google-123',
      };
      mockUserRepo.findByOAuthId.mockResolvedValue(null);
      mockUserRepo.findByEmail.mockResolvedValue(null);
      mockUserRepo.createOAuthUser.mockResolvedValue(newOAuthUser);
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined);

      const result = await authService.oauthLogin({
        profile: mockProfile,
        providerName: 'google',
      });

      expect(mockUserRepo.createOAuthUser).toHaveBeenCalledWith({
        email: 'oauth@example.com',
        oauthProvider: 'google',
        oauthId: 'google-123',
        isVerified: true,
      });
      expect(result.user.email).toBe('oauth@example.com');
    });

    it('should throw AuthError when OAuth user creation fails', async () => {
      mockUserRepo.findByOAuthId.mockResolvedValue(null);
      mockUserRepo.findByEmail.mockResolvedValue(null);
      mockUserRepo.createOAuthUser.mockResolvedValue(null as never);

      await expect(
        authService.oauthLogin({
          profile: mockProfile,
          providerName: 'google',
        })
      ).rejects.toThrow(AuthError);
    });

    it('should write audit log for OAuth login', async () => {
      mockUserRepo.findByOAuthId.mockResolvedValue(mockSafeUser);
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined);

      await authService.oauthLogin({
        profile: mockProfile,
        providerName: 'google',
        ipAddress: '10.0.0.1',
      });

      expect(mockAuditRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockSafeUser.id,
          eventType: 'oauth_login',
          metadata: expect.objectContaining({ provider: 'google' }),
        })
      );
    });
  });
});
