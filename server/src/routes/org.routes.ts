import { FastifyInstance, FastifyPluginCallback } from 'fastify';
import { z } from 'zod';
import { orgService } from '../services/org.service';
import { isAppError } from '../utils/errors';
import { createLogger } from '../utils/logger';
import {
  sendCreated,
  sendError,
  sendSuccess,
  sendValidationError,
} from '../utils/response';
import { authenticate } from '../middleware/authenticate';

const log = createLogger('OrgRoutes');

const createOrgSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255, 'Name too long'),
  slug: z
    .string()
    .min(1, 'Slug is required')
    .max(255, 'Slug too long')
    .toLowerCase()
    .trim(),
});

const updateOrgSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  slug: z.string().min(1).max(255).toLowerCase().trim().optional(),
  logoUrl: z.string().url().max(2048).nullable().optional(),
  metadata: z.record(z.unknown()).optional(),
});

const orgIdParamSchema = z.object({
  orgId: z.string().uuid('Invalid organization ID'),
});

const memberParamSchema = z.object({
  orgId: z.string().uuid('Invalid organization ID'),
  userId: z.string().uuid('Invalid user ID'),
});

const updateMemberRoleSchema = z.object({
  role: z.enum(['owner', 'admin', 'member'], {
    errorMap: () => ({ message: 'Role must be owner, admin, or member' }),
  }),
});

const orgRoutes: FastifyPluginCallback = (
  app: FastifyInstance,
  _options,
  done
) => {
  // All org routes require authentication
  app.addHook('preHandler', authenticate);

  // ── POST /api/orgs — Create organization ──────────────
  app.post('/', async (request, reply) => {
    const parsed = createOrgSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendValidationError(
        reply,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    try {
      const org = await orgService.create({
        name: parsed.data.name,
        slug: parsed.data.slug,
        userId: request.user!.id,
        userRoles: request.user!.roles,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      });

      return sendCreated(reply, { organization: org });
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      log.error({ err, reqId: request.id }, 'Unexpected error creating org');
      throw err;
    }
  });

  // ── GET /api/orgs — List user's organizations ─────────
  app.get('/', async (request, reply) => {
    const orgs = await orgService.list(request.user!.id);
    return sendSuccess(reply, { organizations: orgs });
  });

  // ── GET /api/orgs/:orgId — Get org details ────────────
  app.get('/:orgId', async (request, reply) => {
    const parsed = orgIdParamSchema.safeParse(request.params);
    if (!parsed.success) {
      return sendValidationError(
        reply,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    try {
      const org = await orgService.getById(parsed.data.orgId);
      return sendSuccess(reply, { organization: org });
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      throw err;
    }
  });

  // ── PATCH /api/orgs/:orgId — Update org ───────────────
  app.patch('/:orgId', async (request, reply) => {
    const paramsParsed = orgIdParamSchema.safeParse(request.params);
    if (!paramsParsed.success) {
      return sendValidationError(
        reply,
        paramsParsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    const bodyParsed = updateOrgSchema.safeParse(request.body);
    if (!bodyParsed.success) {
      return sendValidationError(
        reply,
        bodyParsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    try {
      const org = await orgService.update({
        orgId: paramsParsed.data.orgId,
        ...bodyParsed.data,
        userId: request.user!.id,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      });

      return sendSuccess(reply, { organization: org });
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      log.error({ err, reqId: request.id }, 'Unexpected error updating org');
      throw err;
    }
  });

  // ── DELETE /api/orgs/:orgId — Delete org ──────────────
  app.delete('/:orgId', async (request, reply) => {
    const parsed = orgIdParamSchema.safeParse(request.params);
    if (!parsed.success) {
      return sendValidationError(
        reply,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    try {
      await orgService.delete({
        orgId: parsed.data.orgId,
        userId: request.user!.id,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      });

      return sendSuccess(reply, { message: 'Organization deleted' });
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      log.error({ err, reqId: request.id }, 'Unexpected error deleting org');
      throw err;
    }
  });

  // ── GET /api/orgs/:orgId/members — List members ───────
  app.get('/:orgId/members', async (request, reply) => {
    const parsed = orgIdParamSchema.safeParse(request.params);
    if (!parsed.success) {
      return sendValidationError(
        reply,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    try {
      const members = await orgService.listMembers(parsed.data.orgId);
      return sendSuccess(reply, { members });
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      throw err;
    }
  });

  // ── PATCH /api/orgs/:orgId/members/:userId — Update role
  app.patch('/:orgId/members/:userId', async (request, reply) => {
    const paramsParsed = memberParamSchema.safeParse(request.params);
    if (!paramsParsed.success) {
      return sendValidationError(
        reply,
        paramsParsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    const bodyParsed = updateMemberRoleSchema.safeParse(request.body);
    if (!bodyParsed.success) {
      return sendValidationError(
        reply,
        bodyParsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    try {
      await orgService.updateMemberRole({
        orgId: paramsParsed.data.orgId,
        targetUserId: paramsParsed.data.userId,
        newRole: bodyParsed.data.role,
        actorUserId: request.user!.id,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      });

      return sendSuccess(reply, { message: 'Member role updated' });
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      log.error(
        { err, reqId: request.id },
        'Unexpected error updating member role'
      );
      throw err;
    }
  });

  // ── DELETE /api/orgs/:orgId/members/:userId — Remove member
  app.delete('/:orgId/members/:userId', async (request, reply) => {
    const parsed = memberParamSchema.safeParse(request.params);
    if (!parsed.success) {
      return sendValidationError(
        reply,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    try {
      await orgService.removeMember({
        orgId: parsed.data.orgId,
        targetUserId: parsed.data.userId,
        actorUserId: request.user!.id,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      });

      return sendSuccess(reply, { message: 'Member removed' });
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      log.error({ err, reqId: request.id }, 'Unexpected error removing member');
      throw err;
    }
  });

  done();
};

export { orgRoutes };
