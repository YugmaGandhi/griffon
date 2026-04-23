import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { authenticate } from '../middleware/authenticate';
import { authorize } from '../middleware/authorize';
import { requireInteractiveAuth } from '../middleware/require-interactive-auth';
import { isAppError } from '../utils/errors';
import { createLogger } from '../utils/logger';
import {
  sendSuccess,
  sendCreated,
  sendError,
  sendPaginated,
  sendValidationError,
} from '../utils/response';
import { auditRepository } from '../repositories/audit.repository';
import { adminService } from '../services/admin.service';
import { deletionService } from '../services/deletion.service';
import { mfaService } from '../services/mfa.service';
import { apiKeyService } from '../services/api-key.service';

const log = createLogger('AdminRoutes');

// ── Schemas ───────────────────────────────────────────────
const auditLogsQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  userId: z.string().uuid().optional(),
});

const listUsersQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  email: z.string().optional(),
  isDisabled: z
    .enum(['true', 'false'])
    .transform((v) => v === 'true')
    .optional(),
  isLocked: z
    .enum(['true', 'false'])
    .transform((v) => v === 'true')
    .optional(),
});

const createUserBodySchema = z.object({
  email: z.string().email('Invalid email format').toLowerCase().trim(),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password too long'),
});

const updateUserBodySchema = z
  .object({
    email: z
      .string()
      .email('Invalid email format')
      .toLowerCase()
      .trim()
      .optional(),
    isVerified: z.boolean().optional(),
  })
  .refine((body) => Object.keys(body).length > 0, {
    message: 'At least one field must be provided',
  });

const userIdParamSchema = z.object({
  id: z.string().uuid('Invalid user ID'),
});

// ── Routes ────────────────────────────────────────────────
export function adminRoutes(
  app: FastifyInstance,
  _options: unknown,
  done: () => void
) {
  // ── GET /api/admin/audit-logs ─────────────────────────
  app.get(
    '/audit-logs',
    { preHandler: [authenticate, authorize('read:audit-logs')] },
    async (request, reply) => {
      const parsed = auditLogsQuerySchema.safeParse(request.query);
      if (!parsed.success) {
        return sendValidationError(
          reply,
          parsed.error.issues.map((i) => ({
            field: i.path.join('.'),
            message: i.message,
          }))
        );
      }

      const logs = await auditRepository.findAll(parsed.data);
      return sendSuccess(reply, {
        logs,
        meta: { page: parsed.data.page, limit: parsed.data.limit },
      });
    }
  );

  // ── GET /api/admin/users ──────────────────────────────
  app.get(
    '/users',
    { preHandler: [authenticate, authorize('read:users')] },
    async (request, reply) => {
      const parsed = listUsersQuerySchema.safeParse(request.query);
      if (!parsed.success) {
        return sendValidationError(
          reply,
          parsed.error.issues.map((i) => ({
            field: i.path.join('.'),
            message: i.message,
          }))
        );
      }

      try {
        const result = await adminService.listUsers(parsed.data);
        return sendPaginated(reply, result.users, {
          page: result.page,
          limit: result.limit,
          total: result.total,
          totalPages: result.totalPages,
        });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error({ err, reqId: request.id }, 'Unexpected error listing users');
        throw err;
      }
    }
  );

  // ── POST /api/admin/users ─────────────────────────────
  app.post(
    '/users',
    { preHandler: [authenticate, authorize('write:users')] },
    async (request, reply) => {
      const parsed = createUserBodySchema.safeParse(request.body);
      if (!parsed.success) {
        return sendValidationError(
          reply,
          parsed.error.issues.map((i) => ({
            field: i.path.join('.'),
            message: i.message,
          }))
        );
      }

      try {
        const user = await adminService.createUser({
          email: parsed.data.email,
          password: parsed.data.password,
          adminId: request.user!.id,
          ipAddress: request.ip,
        });
        return sendCreated(reply, { user });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error({ err, reqId: request.id }, 'Unexpected error creating user');
        throw err;
      }
    }
  );

  // ── PATCH /api/admin/users/:id ────────────────────────
  app.patch(
    '/users/:id',
    { preHandler: [authenticate, authorize('write:users')] },
    async (request, reply) => {
      const paramsParsed = userIdParamSchema.safeParse(request.params);
      if (!paramsParsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID');
      }

      const bodyParsed = updateUserBodySchema.safeParse(request.body);
      if (!bodyParsed.success) {
        return sendValidationError(
          reply,
          bodyParsed.error.issues.map((i) => ({
            field: i.path.join('.'),
            message: i.message,
          }))
        );
      }

      try {
        const user = await adminService.updateUser(
          paramsParsed.data.id,
          bodyParsed.data,
          request.user!.id
        );
        return sendSuccess(reply, { user });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error({ err, reqId: request.id }, 'Unexpected error updating user');
        throw err;
      }
    }
  );

  // ── POST /api/admin/users/:id/disable ────────────────
  app.post(
    '/users/:id/disable',
    { preHandler: [authenticate, authorize('write:users')] },
    async (request, reply) => {
      const parsed = userIdParamSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID');
      }

      try {
        await adminService.disableUser(
          parsed.data.id,
          request.user!.id,
          request.ip
        );
        return sendSuccess(reply, { message: 'User disabled successfully' });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error disabling user'
        );
        throw err;
      }
    }
  );

  // ── POST /api/admin/users/:id/enable ─────────────────
  app.post(
    '/users/:id/enable',
    { preHandler: [authenticate, authorize('write:users')] },
    async (request, reply) => {
      const parsed = userIdParamSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID');
      }

      try {
        await adminService.enableUser(
          parsed.data.id,
          request.user!.id,
          request.ip
        );
        return sendSuccess(reply, { message: 'User enabled successfully' });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error({ err, reqId: request.id }, 'Unexpected error enabling user');
        throw err;
      }
    }
  );

  // ── GET /api/admin/users/:id/sessions ─────────────────
  app.get(
    '/users/:id/sessions',
    { preHandler: [authenticate, authorize('read:users')] },
    async (request, reply) => {
      const parsed = userIdParamSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID');
      }

      try {
        const sessions = await adminService.getUserSessions(parsed.data.id);
        return sendSuccess(reply, { sessions });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error fetching user sessions'
        );
        throw err;
      }
    }
  );

  // ── DELETE /api/admin/users/:id/sessions ──────────────
  app.delete(
    '/users/:id/sessions',
    { preHandler: [authenticate, authorize('write:users')] },
    async (request, reply) => {
      const parsed = userIdParamSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID');
      }

      try {
        await adminService.revokeAllUserSessions(
          parsed.data.id,
          request.user!.id,
          request.ip
        );
        return sendSuccess(reply, {
          message: 'All sessions revoked successfully',
        });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error revoking user sessions'
        );
        throw err;
      }
    }
  );

  // ── POST /api/admin/users/:id/delete — force-delete ───
  app.post(
    '/users/:id/delete',
    { preHandler: [authenticate, authorize('write:users')] },
    async (request, reply) => {
      const parsed = userIdParamSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID');
      }

      try {
        await deletionService.forceDelete({
          userId: parsed.data.id,
          adminId: request.user!.id,
          ipAddress: request.ip,
        });
        return sendSuccess(reply, {
          message: 'User account permanently deleted',
        });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error force-deleting user'
        );
        throw err;
      }
    }
  );

  // ── DELETE /api/admin/users/:id/mfa — Force-disable MFA ─
  // Admin bypass — does not require the user's TOTP code.
  // Used when a user loses access to their authenticator and contacts support.
  app.delete(
    '/users/:id/mfa',
    { preHandler: [authenticate, authorize('write:users')] },
    async (request, reply) => {
      const parsed = userIdParamSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID');
      }

      try {
        await mfaService.adminDisableMfa({
          targetUserId: parsed.data.id,
          adminId: request.user!.id,
          ipAddress: request.ip,
        });
        return sendSuccess(reply, {
          message: 'MFA disabled for user',
        });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error force-disabling MFA'
        );
        throw err;
      }
    }
  );

  // ── GET /api/admin/users/:id/api-keys — List user's keys ─
  app.get(
    '/users/:id/api-keys',
    {
      preHandler: [
        authenticate,
        requireInteractiveAuth,
        authorize('read:users'),
      ],
    },
    async (request, reply) => {
      const parsed = userIdParamSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID');
      }

      try {
        const keys = await apiKeyService.adminListKeys(parsed.data.id);
        return sendSuccess(reply, { keys });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error listing user API keys'
        );
        throw err;
      }
    }
  );

  // ── DELETE /api/admin/users/:id/api-keys/:keyId — Revoke ─
  // Admin bypass — no caller ownership check, no MFA gate.
  // The key must still belong to the target user named by :id.
  const adminKeyParamSchema = z.object({
    id: z.string().uuid('Invalid user ID'),
    keyId: z.string().uuid('Invalid API key ID'),
  });

  app.delete(
    '/users/:id/api-keys/:keyId',
    {
      preHandler: [
        authenticate,
        requireInteractiveAuth,
        authorize('write:users'),
      ],
    },
    async (request, reply) => {
      const parsed = adminKeyParamSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid parameters');
      }

      try {
        await apiKeyService.adminRevokeKey({
          keyId: parsed.data.keyId,
          targetUserId: parsed.data.id,
          adminId: request.user!.id,
          ipAddress: request.ip,
        });
        return sendSuccess(reply, { message: 'API key revoked' });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error revoking user API key'
        );
        throw err;
      }
    }
  );

  done();
}
