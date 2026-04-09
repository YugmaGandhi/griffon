import { userRepository } from '../repositories/user.repository';
import { auditRepository } from '../repositories/audit.repository';
import { tokenRepository } from '../repositories/token.repository';
import { emailTokenRepository } from '../repositories/email-token.repository';
import { rbacService } from './rbac.service';
import { emailService } from './email.service';
import { passwordService } from './password.service';
import { redis } from '../db/redis';
import { ConflictError, NotFoundError } from '../utils/errors';
import { createLogger } from '../utils/logger';

const log = createLogger('AdminService');

// Blocklist TTL matches max refresh token lifetime (30 days)
// Access tokens expire in 15 min, but this covers edge cases
const BLOCKLIST_TTL_SECONDS = 30 * 24 * 60 * 60;

type ListUsersParams = {
  page: number;
  limit: number;
  email?: string;
  isDisabled?: boolean;
  isLocked?: boolean;
};

type CreateUserParams = {
  email: string;
  password: string;
  adminId: string;
  ipAddress?: string;
};

type UpdateUserParams = {
  email?: string;
  isVerified?: boolean;
};

export class AdminService {
  // ── List Users ────────────────────────────────────────
  async listUsers(params: ListUsersParams) {
    log.debug(params, 'Admin listing users');
    const { users, total } = await userRepository.findAllPaginated(params);
    const totalPages = Math.ceil(total / params.limit);
    return { users, total, page: params.page, limit: params.limit, totalPages };
  }

  // ── Create User ───────────────────────────────────────
  async createUser({ email, password, adminId, ipAddress }: CreateUserParams) {
    log.info({ email, adminId }, 'Admin creating user');

    const existing = await userRepository.findByEmail(email);
    if (existing) {
      throw new ConflictError(
        'EMAIL_ALREADY_EXISTS',
        'An account with this email already exists'
      );
    }

    const passwordHash = await passwordService.hash(password);
    const user = await userRepository.create({
      email: email.toLowerCase().trim(),
      passwordHash,
    });

    await rbacService.assignDefaultRole(user.id);

    // Create email verification token and send welcome email
    const rawToken = await emailTokenRepository.create(
      user.id,
      'email_verification',
      24
    );
    void emailService.sendVerificationEmail(user.email, rawToken);

    void auditRepository.create({
      userId: adminId,
      eventType: 'user_created_by_admin',
      ipAddress,
      metadata: { targetUserId: user.id, email },
    });

    log.info({ userId: user.id, adminId }, 'User created by admin');
    return user;
  }

  // ── Update User ───────────────────────────────────────
  async updateUser(id: string, data: UpdateUserParams, adminId: string) {
    log.info({ userId: id, adminId }, 'Admin updating user');

    if (data.email) {
      const existing = await userRepository.findByEmail(data.email);
      if (existing && existing.id !== id) {
        throw new ConflictError(
          'EMAIL_ALREADY_EXISTS',
          'This email is already in use'
        );
      }
    }

    const user = await userRepository.updateUser(id, data);
    if (!user) {
      throw new NotFoundError('USER_NOT_FOUND', 'User not found');
    }

    return user;
  }

  // ── Disable User ──────────────────────────────────────
  // Sets isDisabled=true in DB, adds to Redis blocklist, revokes all sessions
  async disableUser(id: string, adminId: string, ipAddress?: string) {
    log.warn({ userId: id, adminId }, 'Admin disabling user');

    const user = await userRepository.findById(id);
    if (!user) {
      throw new NotFoundError('USER_NOT_FOUND', 'User not found');
    }

    await userRepository.disableUser(id);
    await tokenRepository.revokeAllForUser(id);
    await redis.set(`blocklist:user:${id}`, '1', 'EX', BLOCKLIST_TTL_SECONDS);

    void auditRepository.create({
      userId: adminId,
      eventType: 'user_disabled',
      ipAddress,
      metadata: { targetUserId: id },
    });

    log.warn({ userId: id, adminId }, 'User disabled');
  }

  // ── Enable User ───────────────────────────────────────
  // Clears isDisabled in DB, removes from Redis blocklist
  async enableUser(id: string, adminId: string, ipAddress?: string) {
    log.info({ userId: id, adminId }, 'Admin enabling user');

    const user = await userRepository.findById(id);
    if (!user) {
      throw new NotFoundError('USER_NOT_FOUND', 'User not found');
    }

    await userRepository.enableUser(id);
    await redis.del(`blocklist:user:${id}`);

    void auditRepository.create({
      userId: adminId,
      eventType: 'user_enabled',
      ipAddress,
      metadata: { targetUserId: id },
    });

    log.info({ userId: id, adminId }, 'User enabled');
  }

  // ── Get User Sessions (admin view) ────────────────────
  async getUserSessions(userId: string) {
    log.debug({ userId }, 'Admin fetching user sessions');

    const user = await userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('USER_NOT_FOUND', 'User not found');
    }

    return tokenRepository.findActiveSessions(userId);
  }

  // ── Revoke All User Sessions (admin) ──────────────────
  async revokeAllUserSessions(
    userId: string,
    adminId: string,
    ipAddress?: string
  ) {
    log.warn({ userId, adminId }, 'Admin revoking all sessions for user');

    const user = await userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('USER_NOT_FOUND', 'User not found');
    }

    await tokenRepository.revokeAllForUser(userId);

    void auditRepository.create({
      userId: adminId,
      eventType: 'all_sessions_revoked',
      ipAddress,
      metadata: { targetUserId: userId, revokedBy: 'admin' },
    });
  }
}

export const adminService = new AdminService();
