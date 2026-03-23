import { userRepository } from '../repositories/user.repository';
import { auditRepository } from '../repositories/audit.repository';
import { passwordService } from './password.service';
import { AuthError, ConflictError, ForbiddenError } from '../utils/errors';
import { SafeUser, TokenUser, toSafeUser } from '../utils/types';
import { createLogger } from '../utils/logger';
import { tokenService } from './token.service';
import { tokenRepository } from '../repositories/token.repository';

const log = createLogger('AuthService');

type RegisterParams = {
  email: string;
  password: string;
  ipAddress?: string;
  userAgent?: string;
};

type RegisterResult = {
  user: SafeUser;
  message: string;
};

type LoginParams = {
  email: string;
  password: string;
  ipAddress?: string;
  userAgent?: string;
};

type LoginResult = {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  user: SafeUser & { roles: string[]; permissions: string[] };
};

export class AuthService {
  async register(params: RegisterParams): Promise<RegisterResult> {
    const { email, password, ipAddress, userAgent } = params;

    log.info({ email }, 'Registering new user');

    // Step 1 — Check if email already exists
    const existing = await userRepository.findByEmail(email);
    if (existing) {
      log.warn({ email }, 'Registration failed — email already exists');
      throw new ConflictError(
        'EMAIL_ALREADY_EXISTS',
        'An account with this email already exists'
      );
    }

    // Step 2 — Hash the password
    const passwordHash = await passwordService.hash(password);

    // Step 3 — Create the user
    const user = await userRepository.create({
      email: email.toLowerCase().trim(),
      passwordHash,
    });

    // Step 4 — Write audit log
    // Fire and forget — don't await, don't block the response
    void auditRepository.create({
      userId: user.id,
      eventType: 'user_registered',
      ipAddress,
      userAgent,
      metadata: { email },
    });

    log.info({ userId: user.id, email }, 'User registered successfully');

    return {
      user,
      message:
        'Account created successfully. Please check your email to verify your account.',
    };
  }

  async login(params: LoginParams): Promise<LoginResult> {
    const { email, password, ipAddress, userAgent } = params;

    log.info({ email }, 'Login attempt');

    // Step 1 — Find user
    // Use generic error message — never reveal if email exists
    const user = await userRepository.findByEmail(email);
    if (!user) {
      log.warn({ email }, 'Login failed — user not found');
      void auditRepository.create({
        eventType: 'login_failed',
        ipAddress,
        metadata: { email, reason: 'user_not_found' },
      });
      throw new AuthError('INVALID_CREDENTIALS', 'Invalid email or password');
    }

    // Step 2 — Check if account is locked
    if (user.isLocked) {
      // Check if lockout period has expired
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        log.warn({ userId: user.id }, 'Login failed — account locked');
        throw new AuthError(
          'ACCOUNT_LOCKED',
          'Account temporarily locked due to too many failed attempts',
          423
        );
      }
      // Lockout expired — reset it
      await userRepository.resetFailedAttempts(user.id);
    }

    // Step 3 — Check email verified
    if (!user.isVerified) {
      log.warn({ userId: user.id }, 'Login failed — email not verified');
      throw new ForbiddenError(
        'EMAIL_NOT_VERIFIED',
        'Please verify your email address before logging in'
      );
    }

    // Step 4 — Verify password
    const passwordValid = await passwordService.verify(
      password,
      user.passwordHash ?? ''
    );

    if (!passwordValid) {
      log.warn({ userId: user.id }, 'Login failed — invalid password');

      // Increment failed attempts
      await userRepository.incrementFailedAttempts(user.id);

      // Check if we should lock the account
      const maxAttempts = 5;
      if (user.failedAttempts + 1 >= maxAttempts) {
        const lockUntil = new Date();
        lockUntil.setMinutes(lockUntil.getMinutes() + 15);
        await userRepository.lockAccount(user.id, lockUntil);

        void auditRepository.create({
          userId: user.id,
          eventType: 'account_locked',
          ipAddress,
          metadata: { reason: 'max_failed_attempts' },
        });

        throw new AuthError(
          'ACCOUNT_LOCKED',
          'Account temporarily locked due to too many failed attempts',
          423
        );
      }

      void auditRepository.create({
        userId: user.id,
        eventType: 'login_failed',
        ipAddress,
        metadata: { reason: 'invalid_password' },
      });

      throw new AuthError('INVALID_CREDENTIALS', 'Invalid email or password');
    }

    // Step 5 — Generate tokens
    // Build token user — roles/permissions will come from DB in Week 5
    // For now default to basic user role
    const tokenUser: TokenUser = {
      id: user.id,
      email: user.email,
      roles: ['user'],
      permissions: ['read:profile', 'write:profile'],
    };

    const accessToken = await tokenService.generateAccessToken(tokenUser);
    const rawRefreshToken = tokenService.generateRefreshToken();
    const refreshTokenHash = tokenService.hashRefreshToken(rawRefreshToken);

    // Step 6 — Store refresh token
    await tokenRepository.create({
      userId: user.id,
      tokenHash: refreshTokenHash,
      deviceInfo: userAgent,
      ipAddress,
      expiresAt: tokenService.getRefreshTokenExpiry(),
    });

    // Step 7 — Reset failed attempts + update last login
    await userRepository.resetFailedAttempts(user.id);
    await userRepository.updateLastLogin(user.id);

    // Step 8 — Audit log
    void auditRepository.create({
      userId: user.id,
      eventType: 'user_login',
      ipAddress,
      userAgent,
      metadata: { email },
    });

    log.info({ userId: user.id }, 'Login successful');

    // Access token expires in 15 minutes = 900 seconds
    const expiresIn = 900;

    return {
      accessToken,
      refreshToken: rawRefreshToken,
      expiresIn,
      user: {
        ...toSafeUser(user),
        roles: tokenUser.roles,
        permissions: tokenUser.permissions,
      },
    };
  }

  // ── Logout ───────────────────────────────────────────────
  async logout(params: {
    refreshToken: string;
    userId: string;
    ipAddress?: string;
  }): Promise<void> {
    const { refreshToken, userId, ipAddress } = params;

    log.info({ userId }, 'Logout attempt');

    // Find all active tokens for user and check which one matches
    // We can't query by raw token — we stored the hash
    // So we find by userId and verify each one
    const tokenHash = tokenService.hashRefreshToken(refreshToken);
    const storedToken = await tokenRepository.findByHash(tokenHash);

    if (storedToken) {
      await tokenRepository.revoke(storedToken.id);
    }

    void auditRepository.create({
      userId,
      eventType: 'user_logout',
      ipAddress,
      metadata: {},
    });

    log.info({ userId }, 'Logout successful');
  }

  // ── Refresh Token ────────────────────────────────────────
  async refreshTokens(params: {
    refreshToken: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<Omit<LoginResult, 'user'>> {
    const { refreshToken, ipAddress, userAgent } = params;

    log.info('Token refresh attempt');

    // Step 1 — Hash the incoming token and look it up
    const tokenHash = tokenService.hashRefreshToken(refreshToken);
    const storedToken = await tokenRepository.findByHash(tokenHash);

    if (!storedToken) {
      log.warn('Refresh failed — token not found or already revoked');
      throw new AuthError(
        'TOKEN_REVOKED',
        'This session has been revoked. Please log in again.'
      );
    }

    // Step 2 — Check expiry
    if (storedToken.expiresAt < new Date()) {
      log.warn('Refresh failed — token expired');
      throw new AuthError(
        'TOKEN_EXPIRED',
        'Your session has expired. Please log in again.'
      );
    }

    // Step 3 — Get user
    const user = await userRepository.findById(storedToken.userId);
    if (!user) {
      throw new AuthError('TOKEN_INVALID', 'Invalid authentication token');
    }

    // Step 4 — Revoke old token immediately (single use)
    await tokenRepository.revoke(storedToken.id);

    // Step 5 — Generate new token pair
    const tokenUser: TokenUser = {
      id: user.id,
      email: user.email,
      roles: ['user'],
      permissions: ['read:profile', 'write:profile'],
    };

    const newAccessToken = await tokenService.generateAccessToken(tokenUser);
    const newRawRefreshToken = tokenService.generateRefreshToken();
    const newRefreshTokenHash =
      tokenService.hashRefreshToken(newRawRefreshToken);

    // Step 6 — Store new refresh token
    await tokenRepository.create({
      userId: user.id,
      tokenHash: newRefreshTokenHash,
      deviceInfo: userAgent,
      ipAddress,
      expiresAt: tokenService.getRefreshTokenExpiry(),
    });

    void auditRepository.create({
      userId: user.id,
      eventType: 'token_refreshed',
      ipAddress,
      metadata: {},
    });

    log.info({ userId: user.id }, 'Token refresh successful');

    return {
      accessToken: newAccessToken,
      refreshToken: newRawRefreshToken,
      expiresIn: 900,
    };
  }

  // ── Get Current User ─────────────────────────────────────
  async getMe(userId: string): Promise<
    SafeUser & {
      roles: string[];
      permissions: string[];
    }
  > {
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new AuthError('TOKEN_INVALID', 'Invalid authentication token');
    }

    return {
      ...user,
      roles: ['user'],
      permissions: ['read:profile', 'write:profile'],
    };
  }
}

export const authService = new AuthService();
