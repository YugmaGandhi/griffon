import { FastifyInstance, FastifyPluginCallback } from 'fastify';
import { z } from 'zod';
import { webhookService } from '../services/webhook.service';
import { isAppError } from '../utils/errors';
import { createLogger } from '../utils/logger';
import {
  sendCreated,
  sendError,
  sendSuccess,
  sendValidationError,
} from '../utils/response';
import { authenticate } from '../middleware/authenticate';

const log = createLogger('WebhookRoutes');

// ── Schemas ───────────────────────────────────────────────

const orgWebhookParamSchema = z.object({
  orgId: z.string().uuid('Invalid organization ID'),
});

const endpointParamSchema = z.object({
  orgId: z.string().uuid('Invalid organization ID'),
  endpointId: z.string().uuid('Invalid endpoint ID'),
});

const createEndpointSchema = z.object({
  url: z.string().url('Invalid URL').max(2048, 'URL too long'),
  events: z
    .array(z.string().min(1))
    .min(1, 'At least one event type is required'),
});

const updateEndpointSchema = z.object({
  url: z.string().url('Invalid URL').max(2048, 'URL too long').optional(),
  events: z.array(z.string().min(1)).min(1).optional(),
  isActive: z.boolean().optional(),
});

// ── Route plugin ──────────────────────────────────────────
// Registered at /api/orgs/:orgId/webhooks via app.ts

export const webhookRoutes: FastifyPluginCallback = (
  app: FastifyInstance,
  _options,
  done
) => {
  app.addHook('preHandler', authenticate);

  // ── POST /api/orgs/:orgId/webhooks — Register endpoint ─
  // Returns the signing secret once — it is NOT stored and cannot be recovered.
  app.post<{ Params: { orgId: string } }>('/', async (request, reply) => {
    const paramParsed = orgWebhookParamSchema.safeParse(request.params);
    if (!paramParsed.success) {
      return sendValidationError(
        reply,
        paramParsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        }))
      );
    }

    const bodyParsed = createEndpointSchema.safeParse(request.body);
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
      const { endpoint, secret } = await webhookService.registerEndpoint({
        actorUserId: request.user!.id,
        orgId: paramParsed.data.orgId,
        url: bodyParsed.data.url,
        events: bodyParsed.data.events,
      });

      return sendCreated(reply, {
        endpoint,
        // Shown once — customer must save immediately
        secret,
      });
    } catch (err) {
      if (isAppError(err))
        return sendError(reply, err.statusCode, err.code, err.message);
      log.error(
        { err, reqId: request.id },
        'Unexpected error registering webhook endpoint'
      );
      throw err;
    }
  });

  // ── GET /api/orgs/:orgId/webhooks — List endpoints ─────
  app.get<{ Params: { orgId: string } }>('/', async (request, reply) => {
    const paramParsed = orgWebhookParamSchema.safeParse(request.params);
    if (!paramParsed.success) {
      return sendValidationError(
        reply,
        paramParsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        }))
      );
    }

    try {
      const endpoints = await webhookService.listEndpoints({
        actorUserId: request.user!.id,
        orgId: paramParsed.data.orgId,
      });
      return sendSuccess(reply, { endpoints });
    } catch (err) {
      if (isAppError(err))
        return sendError(reply, err.statusCode, err.code, err.message);
      log.error(
        { err, reqId: request.id },
        'Unexpected error listing webhook endpoints'
      );
      throw err;
    }
  });

  // ── PATCH /api/orgs/:orgId/webhooks/:endpointId — Update ─
  app.patch<{ Params: { orgId: string; endpointId: string } }>(
    '/:endpointId',
    async (request, reply) => {
      const paramParsed = endpointParamSchema.safeParse(request.params);
      if (!paramParsed.success) {
        return sendValidationError(
          reply,
          paramParsed.error.issues.map((i) => ({
            field: i.path.join('.'),
            message: i.message,
          }))
        );
      }

      const bodyParsed = updateEndpointSchema.safeParse(request.body);
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
        const endpoint = await webhookService.updateEndpoint({
          actorUserId: request.user!.id,
          endpointId: paramParsed.data.endpointId,
          orgId: paramParsed.data.orgId,
          updates: bodyParsed.data,
        });
        return sendSuccess(reply, { endpoint });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error updating webhook endpoint'
        );
        throw err;
      }
    }
  );

  // ── DELETE /api/orgs/:orgId/webhooks/:endpointId — Delete ─
  app.delete<{ Params: { orgId: string; endpointId: string } }>(
    '/:endpointId',
    async (request, reply) => {
      const paramParsed = endpointParamSchema.safeParse(request.params);
      if (!paramParsed.success) {
        return sendValidationError(
          reply,
          paramParsed.error.issues.map((i) => ({
            field: i.path.join('.'),
            message: i.message,
          }))
        );
      }

      try {
        await webhookService.deleteEndpoint({
          actorUserId: request.user!.id,
          endpointId: paramParsed.data.endpointId,
          orgId: paramParsed.data.orgId,
        });
        return sendSuccess(reply, { message: 'Webhook endpoint deleted' });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error deleting webhook endpoint'
        );
        throw err;
      }
    }
  );

  // ── GET /api/orgs/:orgId/webhooks/:endpointId/deliveries ─
  app.get<{ Params: { orgId: string; endpointId: string } }>(
    '/:endpointId/deliveries',
    async (request, reply) => {
      const paramParsed = endpointParamSchema.safeParse(request.params);
      if (!paramParsed.success) {
        return sendValidationError(
          reply,
          paramParsed.error.issues.map((i) => ({
            field: i.path.join('.'),
            message: i.message,
          }))
        );
      }

      try {
        const deliveries = await webhookService.listDeliveries({
          actorUserId: request.user!.id,
          endpointId: paramParsed.data.endpointId,
          orgId: paramParsed.data.orgId,
        });
        return sendSuccess(reply, { deliveries });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error listing webhook deliveries'
        );
        throw err;
      }
    }
  );

  // ── POST /api/orgs/:orgId/webhooks/:endpointId/test ────
  app.post<{ Params: { orgId: string; endpointId: string } }>(
    '/:endpointId/test',
    async (request, reply) => {
      const paramParsed = endpointParamSchema.safeParse(request.params);
      if (!paramParsed.success) {
        return sendValidationError(
          reply,
          paramParsed.error.issues.map((i) => ({
            field: i.path.join('.'),
            message: i.message,
          }))
        );
      }

      try {
        await webhookService.sendTestEvent({
          actorUserId: request.user!.id,
          endpointId: paramParsed.data.endpointId,
          orgId: paramParsed.data.orgId,
        });
        return sendSuccess(reply, { message: 'Test event sent' });
      } catch (err) {
        if (isAppError(err))
          return sendError(reply, err.statusCode, err.code, err.message);
        log.error(
          { err, reqId: request.id },
          'Unexpected error sending test webhook event'
        );
        throw err;
      }
    }
  );

  done();
};
