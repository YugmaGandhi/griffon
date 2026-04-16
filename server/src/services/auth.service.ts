import { userRepository } from '../repositories/user.repository';
import { orgRepository } from '../repositories/org.repository';
import { auditRepository } from '../repositories/audit.repository';
import { passwordService } from './password.service';
import { AuthError, ConflictError, ForbiddenError } from '../utils/errors';
import { Organization, SafeUser, TokenUser, toSafeUser } from '../utils/types';
import { createLogger } from '../utils/logger';
import { tokenService } from './token.service';
import { tokenRepository } from '../repositories/token.repository';
import { emailTokenRepository } from '../repositories/email-token.repository';
import { emailService } from './email.service';
import { OAuthProfile } from '../config/oauth-providers';
import { rbacService } from './rbac.service';
import { authEventsTotal } from '../utils/metrics';
import { webhookService } from './webhook.service';
import { mfaService } from './mfa.service';
import { redis } from '../db/redis';

const log = createLogger('AuthService');

// TODO: Move audit logging to an async event queue (e.g. Redis Streams)
// Currently we await audit writes directly in the request path (~2-5ms).
// Production IDPs (Auth0, Okta) use event pipelines so audit logging
// never blocks the response. When Griffon needs to handle high throughput,
// publish audit events to a queue and consume them in a background worker.

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

// Full token result — returned when credentials pass and MFA is not required.
// Also used by verifyMfaAndLogin() and oauthLogin() when MFA is cleared.
export type LoginSuccess = {
  mfaRequired: false;
  sessionId: string;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  user: SafeUser & { roles: string[]; permissions: string[] };
  organizations: (Organization & { role: string; joinedAt: Date })[];
};

// Returned by login() when MFA is enabled — client must complete step 2.
// mfaToken is a short-lived opaque token (5-min TTL in Redis).
export type MfaChallengeResult = {
  mfaRequired: true;
  mfaToken: string;
};

// Union of both — what login() and oauthLogin() actually return.
type LoginResult = LoginSuccess | MfaChallengeResult;

// TTL for the MFA challenge token in Redis (5 minutes)
const MFA_CHALLENGE_TTL_SECONDS = 300;

export class AuthService {
  // ── Resolve org claims from user's activeOrgId ────────
  // Called before every token generation. Reads activeOrgId from the user
  // record and resolves their org role + custom role permissions.
  // Returns null fields if user has no active org.
  private async resolveOrgContext(
    userId: string,
    activeOrgId: string | null
  ): Promise<{
    orgId: string | null;
    orgRole: string | null;
    orgPermissions: string[];
  }> {
    if (!activeOrgId) {
      return { orgId: null, orgRole: null, orgPermissions: [] };
    }

    const ctx = await orgRepository.getMemberOrgContext(activeOrgId, userId);
    if (!ctx) {
      // activeOrgId set but user is no longer a member — clear it gracefully
      await userRepository.setActiveOrg(userId, null);
      return { orgId: null, orgRole: null, orgPermissions: [] };
    }

    return {
      orgId: activeOrgId,
      orgRole: ctx.role,
      orgPermissions: ctx.permissions,
    };
  }

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

    // Assign default 'user' role
    await rbacService.assignDefaultRole(user.id);

    // Setp 4 - Send verification email — fire and forget
    // Don't block the response if email fails
    void this.sendVerificationEmail(user.id, user.email);

    // Step 5 — Write audit log
    await auditRepository.create({
      userId: user.id,
      eventType: 'user_registered',
      ipAddress,
      userAgent,
      metadata: { email },
    });

    authEventsTotal.inc({ event: 'register' });
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
      await auditRepository.create({
        eventType: 'login_failed',
        ipAddress,
        metadata: { email, reason: 'user_not_found' },
      });
      authEventsTotal.inc({ event: 'login_failed' });
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

        await auditRepository.create({
          userId: user.id,
          eventType: 'account_locked',
          ipAddress,
          metadata: { reason: 'max_failed_attempts' },
        });
        authEventsTotal.inc({ event: 'account_locked' });

        throw new AuthError(
          'ACCOUNT_LOCKED',
          'Account temporarily locked due to too many failed attempts',
          423
        );
      }

      await auditRepository.create({
        userId: user.id,
        eventType: 'login_failed',
        ipAddress,
        metadata: { reason: 'invalid_password' },
      });
      authEventsTotal.inc({ event: 'login_failed' });

      throw new AuthError('INVALID_CREDENTIALS', 'Invalid email or password');
    }

    // Step 5 — Check if account is disabled by admin.
    // Deferred until after password verification so attackers without the
    // correct password get the same INVALID_CREDENTIALS response whether
    // the account is disabled or not — denies a user-enumeration oracle.
    if (user.isDisabled) {
      log.warn({ userId: user.id }, 'Login failed — account disabled');
      throw new ForbiddenError(
        'ACCOUNT_DISABLED',
        'Your account has been disabled. Please contact support.'
      );
    }

    // Step 6 — MFA gate
    // If MFA is enabled, issue a short-lived challenge token instead of real tokens.
    // The client must submit this token + a TOTP code to POST /auth/mfa/verify.
    const mfaEnabled = await mfaService.isMfaEnabled(user.id);
    if (mfaEnabled) {
      const rawMfaToken = tokenService.generateRefreshToken(); // 64 random bytes, base64url
      const mfaTokenHash = tokenService.hashRefreshToken(rawMfaToken);
      await redis.set(
        `mfa:challenge:${mfaTokenHash}`,
        JSON.stringify({ userId: user.id, ipAddress, userAgent }),
        'EX',
        MFA_CHALLENGE_TTL_SECONDS
      );
      log.info({ userId: user.id }, 'MFA challenge issued');
      return { mfaRequired: true, mfaToken: rawMfaToken };
    }

    // Step 7 — Generate tokens
    const { roles, permissions } = await rbacService.getUserRolesAndPermissions(
      user.id
    );
    const orgContext = await this.resolveOrgContext(user.id, user.activeOrgId);

    const tokenUser: TokenUser = {
      id: user.id,
      email: user.email,
      roles,
      permissions,
      ...orgContext,
    };

    const accessToken = await tokenService.generateAccessToken(tokenUser);
    const rawRefreshToken = tokenService.generateRefreshToken();
    const refreshTokenHash = tokenService.hashRefreshToken(rawRefreshToken);

    // Step 7 — Store refresh token
    const session = await tokenRepository.create({
      userId: user.id,
      tokenHash: refreshTokenHash,
      deviceInfo: userAgent,
      ipAddress,
      expiresAt: tokenService.getRefreshTokenExpiry(),
    });

    // Step 8 — Reset failed attempts + update last login
    await userRepository.resetFailedAttempts(user.id);
    await userRepository.updateLastLogin(user.id);

    // Step 9 — Audit log
    await auditRepository.create({
      userId: user.id,
      eventType: 'user_login',
      ipAddress,
      userAgent,
      metadata: { email },
    });

    authEventsTotal.inc({ event: 'login_success' });
    log.info({ userId: user.id }, 'Login successful');

    // Fanout webhook event — fire and forget, never blocks login
    if (orgContext.orgId) {
      void webhookService
        .fanout({
          eventType: 'user.login',
          orgId: orgContext.orgId,
          payload: {
            userId: user.id,
            email: user.email,
            orgId: orgContext.orgId,
            ipAddress: ipAddress ?? null,
          },
        })
        .catch((err: unknown) => log.error({ err }, 'Webhook fanout failed'));
    }

    // Access token expires in 15 minutes = 900 seconds
    const expiresIn = 900;

    const organizations = await orgRepository.findByUserId(user.id);

    return {
      mfaRequired: false,
      sessionId: session.id,
      accessToken,
      refreshToken: rawRefreshToken,
      expiresIn,
      user: {
        ...toSafeUser(user),
        roles: tokenUser.roles,
        permissions: tokenUser.permissions,
      },
      organizations,
    };
  }

  // ── Verify MFA and complete login ─────────────────────
  // Called from POST /auth/mfa/verify.
  // Validates the mfaToken from Redis, verifies the TOTP/recovery code,
  // then issues the real access + refresh token pair.
  async verifyMfaAndLogin(params: {
    mfaToken: string;
    code: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<LoginSuccess> {
    const { mfaToken, code, ipAddress, userAgent } = params;

    // Step 1 — Atomically retrieve and delete the challenge from Redis.
    // getdel ensures only one concurrent caller gets the value — a plain
    // get + del leaves a window where two requests can both read the challenge
    // before either deletes it, breaking the single-use guarantee.
    const mfaTokenHash = tokenService.hashRefreshToken(mfaToken);
    const challengeRaw = await redis.getdel(`mfa:challenge:${mfaTokenHash}`);

    if (!challengeRaw) {
      throw new AuthError(
        'MFA_TOKEN_EXPIRED',
        'MFA session expired or invalid. Please log in again.',
        401
      );
    }

    // Step 2 — Parse the challenge (already deleted from Redis above)
    const challenge = JSON.parse(challengeRaw) as {
      userId: string;
      ipAddress?: string;
      userAgent?: string;
    };

    // Step 3 — Verify the TOTP or recovery code
    await mfaService.verifyLoginCode({
      userId: challenge.userId,
      code,
      ipAddress,
    });

    // Step 4 — Load user for token generation
    const user = await userRepository.findById(challenge.userId);
    if (!user) {
      throw new AuthError('TOKEN_INVALID', 'Invalid authentication token');
    }

    // Step 5 — Generate real token pair (same as login steps 7-9)
    const { roles, permissions } = await rbacService.getUserRolesAndPermissions(
      user.id
    );
    const orgContext = await this.resolveOrgContext(user.id, user.activeOrgId);

    const tokenUser: TokenUser = {
      id: user.id,
      email: user.email,
      roles,
      permissions,
      ...orgContext,
    };

    const accessToken = await tokenService.generateAccessToken(tokenUser);
    const rawRefreshToken = tokenService.generateRefreshToken();
    const refreshTokenHash = tokenService.hashRefreshToken(rawRefreshToken);

    const session = await tokenRepository.create({
      userId: user.id,
      tokenHash: refreshTokenHash,
      deviceInfo: userAgent,
      ipAddress,
      expiresAt: tokenService.getRefreshTokenExpiry(),
    });

    await userRepository.resetFailedAttempts(user.id);
    await userRepository.updateLastLogin(user.id);

    await auditRepository.create({
      userId: user.id,
      eventType: 'user_login',
      ipAddress,
      userAgent,
      metadata: { email: user.email, mfa: true },
    });

    authEventsTotal.inc({ event: 'login_success' });

    if (orgContext.orgId) {
      void webhookService
        .fanout({
          eventType: 'user.login',
          orgId: orgContext.orgId,
          payload: {
            userId: user.id,
            email: user.email,
            orgId: orgContext.orgId,
            ipAddress: ipAddress ?? null,
          },
        })
        .catch((err: unknown) => log.error({ err }, 'Webhook fanout failed'));
    }

    const organizations = await orgRepository.findByUserId(user.id);

    log.info({ userId: user.id }, 'MFA verified — login complete');

    return {
      mfaRequired: false,
      sessionId: session.id,
      accessToken,
      refreshToken: rawRefreshToken,
      expiresIn: 900,
      user: {
        // findById already returns SafeUser — no need to strip passwordHash again
        ...user,
        roles: tokenUser.roles,
        permissions: tokenUser.permissions,
      },
      organizations,
    };
  }

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

    await auditRepository.create({
      userId,
      eventType: 'user_logout',
      ipAddress,
      metadata: {},
    });

    authEventsTotal.inc({ event: 'logout' });
    log.info({ userId }, 'Logout successful');
  }

  async refreshTokens(params: {
    refreshToken: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<Omit<LoginSuccess, 'user' | 'organizations'>> {
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
    const { roles, permissions } = await rbacService.getUserRolesAndPermissions(
      user.id
    );
    const orgContext = await this.resolveOrgContext(user.id, user.activeOrgId);

    const tokenUser: TokenUser = {
      id: user.id,
      email: user.email,
      roles,
      permissions,
      ...orgContext,
    };

    const newAccessToken = await tokenService.generateAccessToken(tokenUser);
    const newRawRefreshToken = tokenService.generateRefreshToken();
    const newRefreshTokenHash =
      tokenService.hashRefreshToken(newRawRefreshToken);

    // Step 6 — Store new refresh token
    const newSession = await tokenRepository.create({
      userId: user.id,
      tokenHash: newRefreshTokenHash,
      deviceInfo: userAgent,
      ipAddress,
      expiresAt: tokenService.getRefreshTokenExpiry(),
    });

    await auditRepository.create({
      userId: user.id,
      eventType: 'token_refreshed',
      ipAddress,
      metadata: {},
    });

    authEventsTotal.inc({ event: 'token_refresh' });
    log.info({ userId: user.id }, 'Token refresh successful');

    return {
      mfaRequired: false,
      sessionId: newSession.id,
      accessToken: newAccessToken,
      refreshToken: newRawRefreshToken,
      expiresIn: 900,
    };
  }

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

    const { roles, permissions } =
      await rbacService.getUserRolesAndPermissions(userId);

    return {
      ...user,
      roles,
      permissions,
    };
  }

  async sendVerificationEmail(userId: string, email: string): Promise<void> {
    const token = await emailTokenRepository.create(
      userId,
      'email_verification',
      24 // expires in 24 hours
    );

    await emailService.sendVerificationEmail(email, token);
  }

  async verifyEmail(token: string): Promise<void> {
    const emailToken = await emailTokenRepository.findValid(
      token,
      'email_verification'
    );

    if (!emailToken) {
      throw new AuthError(
        'TOKEN_INVALID',
        'This verification link is invalid or has already been used',
        400
      );
    }

    // Mark email as verified
    await userRepository.markEmailVerified(emailToken.userId);

    // Mark token as used
    await emailTokenRepository.markUsed(emailToken.id);

    await auditRepository.create({
      userId: emailToken.userId,
      eventType: 'email_verified',
      metadata: {},
    });

    authEventsTotal.inc({ event: 'email_verified' });
    log.info({ userId: emailToken.userId }, 'Email verified successfully');
  }

  async forgotPassword(email: string, ipAddress?: string): Promise<void> {
    log.info({ email }, 'Password reset requested');

    // Always return success — never reveal if email exists
    const user = await userRepository.findByEmail(email);
    if (!user) {
      // Still wait a moment to prevent timing attacks
      await new Promise((resolve) => setTimeout(resolve, 200));
      return;
    }

    const token = await emailTokenRepository.create(
      user.id,
      'password_reset',
      1 // expires in 1 hour
    );

    await emailService.sendPasswordResetEmail(email, token);

    await auditRepository.create({
      userId: user.id,
      eventType: 'password_reset_requested',
      ipAddress,
      metadata: { email },
    });
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const emailToken = await emailTokenRepository.findValid(
      token,
      'password_reset'
    );

    if (!emailToken) {
      throw new AuthError(
        'TOKEN_INVALID',
        'This reset link is invalid or has already been used',
        400
      );
    }

    // Hash new password
    const passwordHash = await passwordService.hash(newPassword);

    // Update password
    await userRepository.updatePassword(emailToken.userId, passwordHash);

    // Mark token as used
    await emailTokenRepository.markUsed(emailToken.id);

    // Revoke ALL refresh tokens — force re-login everywhere
    await tokenRepository.revokeAllForUser(emailToken.userId);

    await auditRepository.create({
      userId: emailToken.userId,
      eventType: 'password_changed',
      metadata: {},
    });

    authEventsTotal.inc({ event: 'password_reset' });
    log.info({ userId: emailToken.userId }, 'Password reset successfully');
  }

  async oauthLogin(params: {
    profile: OAuthProfile;
    providerName: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<LoginResult> {
    const { profile, providerName, ipAddress, userAgent } = params;

    log.info(
      { email: profile.email, provider: providerName },
      'OAuth login attempt'
    );

    // Step 1 — Find existing OAuth user
    let user = await userRepository.findByOAuthId(providerName, profile.id);

    if (!user) {
      // Step 2 — Check if email already exists
      const existingByEmail = await userRepository.findByEmail(profile.email);

      if (existingByEmail) {
        // Link OAuth to existing account
        await userRepository.linkOAuth(
          existingByEmail.id,
          providerName,
          profile.id
        );
        user = await userRepository.findById(existingByEmail.id);
      } else {
        // Step 3 — Create brand new user
        // OAuth users skip email verification
        user = await userRepository.createOAuthUser({
          email: profile.email.toLowerCase().trim(),
          oauthProvider: providerName,
          oauthId: profile.id,
          isVerified: true,
        });
      }
    }

    if (!user) {
      throw new AuthError('INTERNAL_ERROR', 'OAuth login failed', 500);
    }

    // Block disabled accounts from completing OAuth login.
    // Mirrors the guard in login() — admins disable users from a single
    // surface, so OAuth must respect it too.
    if (user.isDisabled) {
      log.warn(
        { userId: user.id, provider: providerName },
        'OAuth login failed — account disabled'
      );
      throw new ForbiddenError(
        'ACCOUNT_DISABLED',
        'Your account has been disabled. Please contact support.'
      );
    }

    // Step 4 — MFA gate (same as password login)
    const mfaEnabled = await mfaService.isMfaEnabled(user.id);
    if (mfaEnabled) {
      const rawMfaToken = tokenService.generateRefreshToken();
      const mfaTokenHash = tokenService.hashRefreshToken(rawMfaToken);
      await redis.set(
        `mfa:challenge:${mfaTokenHash}`,
        JSON.stringify({ userId: user.id, ipAddress, userAgent }),
        'EX',
        MFA_CHALLENGE_TTL_SECONDS
      );
      log.info({ userId: user.id }, 'MFA challenge issued after OAuth');
      return { mfaRequired: true, mfaToken: rawMfaToken };
    }

    // Step 5 — Generate Griffon tokens
    const { roles, permissions } = await rbacService.getUserRolesAndPermissions(
      user.id
    );
    const orgContext = await this.resolveOrgContext(
      user.id,
      user.activeOrgId ?? null
    );

    const tokenUser: TokenUser = {
      id: user.id,
      email: user.email,
      roles,
      permissions,
      ...orgContext,
    };

    const accessToken = await tokenService.generateAccessToken(tokenUser);
    const rawRefreshToken = tokenService.generateRefreshToken();
    const refreshTokenHash = tokenService.hashRefreshToken(rawRefreshToken);

    const oauthSession = await tokenRepository.create({
      userId: user.id,
      tokenHash: refreshTokenHash,
      deviceInfo: userAgent,
      ipAddress,
      expiresAt: tokenService.getRefreshTokenExpiry(),
    });

    await userRepository.updateLastLogin(user.id);

    await auditRepository.create({
      userId: user.id,
      eventType: 'oauth_login',
      ipAddress,
      userAgent,
      metadata: { provider: providerName, email: profile.email },
    });

    authEventsTotal.inc({ event: 'oauth_login' });
    log.info(
      { userId: user.id, provider: providerName },
      'OAuth login successful'
    );

    const organizations = await orgRepository.findByUserId(user.id);

    return {
      mfaRequired: false,
      sessionId: oauthSession.id,
      accessToken,
      refreshToken: rawRefreshToken,
      expiresIn: 900,
      user: {
        // Note: `user` here is already SafeUser — userRepository.findByOAuthId
        // and createOAuthUser both return the sanitized type, so spreading
        // is safe (no passwordHash present).
        ...user,
        roles: tokenUser.roles,
        permissions: tokenUser.permissions,
      },
      organizations,
    };
  }

  async setActiveOrg(params: {
    userId: string;
    orgId: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    const { userId, orgId, ipAddress, userAgent } = params;

    log.info({ userId, orgId }, 'Switching active org');

    // Verify the user is actually a member of the requested org
    const membership = await orgRepository.findMembership(orgId, userId);
    if (!membership) {
      throw new ForbiddenError(
        'FORBIDDEN',
        'You are not a member of this organization'
      );
    }

    // Persist the new active org
    await userRepository.setActiveOrg(userId, orgId);

    // Re-load user for email field
    const user = await userRepository.findById(userId);

    const { roles, permissions } =
      await rbacService.getUserRolesAndPermissions(userId);
    const orgContext = await this.resolveOrgContext(userId, orgId);

    const tokenUser: TokenUser = {
      id: userId,
      email: user!.email,
      roles,
      permissions,
      ...orgContext,
    };

    const accessToken = await tokenService.generateAccessToken(tokenUser);
    const rawRefreshToken = tokenService.generateRefreshToken();
    const refreshTokenHash = tokenService.hashRefreshToken(rawRefreshToken);

    await tokenRepository.create({
      userId,
      tokenHash: refreshTokenHash,
      deviceInfo: userAgent,
      ipAddress,
      expiresAt: tokenService.getRefreshTokenExpiry(),
    });

    await auditRepository.create({
      userId,
      eventType: 'org_switched',
      ipAddress,
      userAgent,
      metadata: { orgId },
    });

    log.info({ userId, orgId }, 'Active org switched');

    return { accessToken, refreshToken: rawRefreshToken, expiresIn: 900 };
  }
}

export const authService = new AuthService();
