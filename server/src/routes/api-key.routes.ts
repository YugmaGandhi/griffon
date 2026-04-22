import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { apiKeyService } from '../services/api-key.service';
import { isAppError } from '../utils/errors';
import { createLogger } from '../utils/logger';
import {
  sendCreated,
  sendError,
  sendSuccess,
  sendValidationError,
} from '../utils/response';
import { authenticate } from '../middleware/authenticate';
import { requireInteractiveAuth } from '../middleware/require-interactive-auth';

const log = createLogger('ApiKeyRoutes');

// ── Schemas ───────────────────────────────────────────────

const createKeySchema = z.object({
  name: z.string().min(1, 'Name is required').max(255, 'Name too long').trim(),
  permissions: z
    .array(z.string().min(1))
    .min(1, 'At least one permission is required'),
  orgId: z.string().uuid('Invalid organization ID').optional().nullable(),
  expiresAt: z.coerce.date().optional().nullable(),
  totpCode: z.string().optional(),
});

const keyIdParamSchema = z.object({
  id: z.string().uuid('Invalid API key ID'),
});

const revokeKeySchema = z.object({
  totpCode: z.string().optional(),
});

// ── Route plugin ──────────────────────────────────────────
// Registered at /api via app.ts

export function apiKeyRoutes(
  app: FastifyInstance,
  _options: unknown,
  done: () => void
) {
  app.addHook('preHandler', authenticate);
  // API-key principals cannot manage API keys — JWT sessions only.
  // See docs/PHASE2.md "API key self-replication" for rationale.
  app.addHook('preHandler', requireInteractiveAuth);

  // ── POST /api/api-keys — Create key ───────────────────
  // Returns the plaintext key once — it is NOT stored and cannot be recovered.
  app.post('/api-keys', async (request, reply) => {
    const parsed = createKeySchema.safeParse(request.body);
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
      const { key, plaintext } = await apiKeyService.createKey({
        userId: request.user!.id,
        callerPermissions: request.user!.permissions,
        orgId: parsed.data.orgId ?? null,
        name: parsed.data.name,
        permissions: parsed.data.permissions,
        expiresAt: parsed.data.expiresAt ?? null,
        totpCode: parsed.data.totpCode,
        ipAddress: request.ip,
      });

      return sendCreated(reply, {
        key,
        // Shown once — caller must save immediately, cannot be retrieved again
        plaintext,
      });
    } catch (err) {
      if (isAppError(err))
        return sendError(reply, err.statusCode, err.code, err.message);
      log.error(
        { err, reqId: request.id },
        'Unexpected error creating API key'
      );
      throw err;
    }
  });

  // ── GET /api/api-keys — List keys ─────────────────────
  app.get('/api-keys', async (request, reply) => {
    try {
      const keys = await apiKeyService.listKeys(request.user!.id);
      return sendSuccess(reply, { keys });
    } catch (err) {
      if (isAppError(err))
        return sendError(reply, err.statusCode, err.code, err.message);
      log.error(
        { err, reqId: request.id },
        'Unexpected error listing API keys'
      );
      throw err;
    }
  });

  // ── GET /api/api-keys/:id — Get single key ────────────
  app.get<{ Params: { id: string } }>(
    '/api-keys/:id',
    async (request, reply) => {
      const parsed = keyIdParamSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid API key ID');
      }

      try {
        const key = await apiKeyService.getKey(
          parsed.data.id,
          request.user!.id
        );
        return sendSuccess(reply, { key });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error fetching API key'
        );
        throw err;
      }
    }
  );

  // ── DELETE /api/api-keys/:id — Revoke key ─────────────
  app.delete<{ Params: { id: string } }>(
    '/api-keys/:id',
    async (request, reply) => {
      const paramParsed = keyIdParamSchema.safeParse(request.params);
      if (!paramParsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid API key ID');
      }

      const bodyParsed = revokeKeySchema.safeParse(request.body ?? {});
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
        await apiKeyService.revokeKey({
          id: paramParsed.data.id,
          userId: request.user!.id,
          totpCode: bodyParsed.data.totpCode,
          ipAddress: request.ip,
        });
        return sendSuccess(reply, { message: 'API key revoked' });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error revoking API key'
        );
        throw err;
      }
    }
  );

  done();
}
