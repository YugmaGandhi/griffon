import crypto from 'crypto';
import { env } from '../config/env';
import { orgRepository } from '../repositories/org.repository';
import { webhookRepository } from '../repositories/webhook.repository';
import {
  ForbiddenError,
  NotFoundError,
  ValidationError,
} from '../utils/errors';
import { createLogger } from '../utils/logger';
import type {
  SafeWebhookEndpoint,
  WebhookDelivery,
  WebhookEndpoint,
} from '../utils/types';
import { toSafeWebhookEndpoint } from '../utils/types';

const log = createLogger('WebhookService');

// ── Retry schedule (exponential backoff) ─────────────────
// Index = attempt number (0-based). Value = delay before next retry in ms.
// After 6 attempts the delivery is marked failed — no more retries.
const RETRY_DELAYS_MS = [
  5_000, // attempt 1 failed → retry in 5s
  30_000, // attempt 2 failed → retry in 30s
  120_000, // attempt 3 failed → retry in 2m
  600_000, // attempt 4 failed → retry in 10m
  1_800_000, // attempt 5 failed → retry in 30m
  7_200_000, // attempt 6 failed → retry in 2h
];
const MAX_ATTEMPTS = RETRY_DELAYS_MS.length;

// ── Secret encryption helpers ─────────────────────────────
// Webhook signing secrets must be HMAC'd at delivery time, so we need the raw
// secret. We encrypt at rest with AES-256-GCM using WEBHOOK_SECRET_KEY rather
// than hashing (which is one-way and can't be recovered for signing).
// Stored format in DB: "<iv_hex>:<authTag_hex>:<ciphertext_hex>"

function encryptSecret(rawSecret: string): string {
  const key = Buffer.from(env.WEBHOOK_SECRET_KEY, 'hex');
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(rawSecret, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${ciphertext.toString('hex')}`;
}

function decryptSecret(stored: string): string {
  const [ivHex, authTagHex, ciphertextHex] = stored.split(':');
  const key = Buffer.from(env.WEBHOOK_SECRET_KEY, 'hex');
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
  return (
    decipher.update(Buffer.from(ciphertextHex, 'hex')).toString('utf8') +
    decipher.final('utf8')
  );
}

// ── HMAC signature ────────────────────────────────────────
// Header sent on every delivery: X-Griffon-Signature: sha256=<hex>
// Customer verifies: compute HMAC-SHA256 over raw request body with their secret.
function signPayload(rawSecret: string, body: string): string {
  return (
    'sha256=' +
    crypto.createHmac('sha256', rawSecret).update(body).digest('hex')
  );
}

export class WebhookService {
  // ── Org membership guards ─────────────────────────────
  // Any member can read (list endpoints, view deliveries).
  // Only admin/owner can write (register, update, delete, test).

  private async assertMember(orgId: string, userId: string): Promise<void> {
    const membership = await orgRepository.findMembership(orgId, userId);
    if (!membership) {
      throw new ForbiddenError(
        'ORG_ACCESS_DENIED',
        'You are not a member of this organization'
      );
    }
  }

  private async assertAdmin(orgId: string, userId: string): Promise<void> {
    const membership = await orgRepository.findMembership(orgId, userId);
    if (!membership) {
      throw new ForbiddenError(
        'ORG_ACCESS_DENIED',
        'You are not a member of this organization'
      );
    }
    if (!['owner', 'admin'].includes(membership.role)) {
      throw new ForbiddenError(
        'INSUFFICIENT_ORG_ROLE',
        'Only org admins and owners can manage webhooks'
      );
    }
  }

  // ── Ownership check on a specific endpoint ────────────
  // Shared by update/delete/deliveries/test — verifies the endpoint
  // belongs to the org the caller is operating on.
  private async assertEndpointOwnership(
    endpointId: string,
    orgId: string
  ): Promise<WebhookEndpoint> {
    const endpoint = await webhookRepository.findById(endpointId);
    if (!endpoint) {
      throw new NotFoundError(
        'WEBHOOK_NOT_FOUND',
        'Webhook endpoint not found'
      );
    }
    if (endpoint.orgId !== orgId) {
      throw new ForbiddenError(
        'WEBHOOK_NOT_IN_ORG',
        'This webhook endpoint does not belong to your organization'
      );
    }
    return endpoint;
  }

  // ── Register endpoint ─────────────────────────────────
  // Returns the raw secret ONCE — not stored, never recoverable.
  // Customer must save it immediately. If lost, they must delete and re-register.
  async registerEndpoint(params: {
    actorUserId: string;
    orgId: string;
    url: string;
    events: string[];
  }): Promise<{ endpoint: SafeWebhookEndpoint; secret: string }> {
    await this.assertAdmin(params.orgId, params.actorUserId);

    if (!params.url.startsWith('https://')) {
      throw new ValidationError('Webhook URLs must use HTTPS');
    }

    if (params.events.length === 0) {
      throw new ValidationError('At least one event type must be specified');
    }

    // Generate 32-byte cryptographically random secret
    const rawSecret = crypto.randomBytes(32).toString('hex');
    const secretHash = encryptSecret(rawSecret);

    const endpoint = await webhookRepository.createEndpoint({
      orgId: params.orgId,
      url: params.url,
      events: params.events,
      secretHash,
    });

    log.info(
      { endpointId: endpoint.id, orgId: params.orgId },
      'Webhook endpoint registered'
    );

    return { endpoint: toSafeWebhookEndpoint(endpoint), secret: rawSecret };
  }

  // ── List endpoints ────────────────────────────────────
  async listEndpoints(params: {
    actorUserId: string;
    orgId: string;
  }): Promise<SafeWebhookEndpoint[]> {
    await this.assertMember(params.orgId, params.actorUserId);
    const endpoints = await webhookRepository.findByOrg(params.orgId);
    return endpoints.map(toSafeWebhookEndpoint);
  }

  // ── Update endpoint ───────────────────────────────────
  async updateEndpoint(params: {
    actorUserId: string;
    endpointId: string;
    orgId: string;
    updates: Partial<{ url: string; events: string[]; isActive: boolean }>;
  }): Promise<SafeWebhookEndpoint> {
    await this.assertAdmin(params.orgId, params.actorUserId);
    await this.assertEndpointOwnership(params.endpointId, params.orgId);

    if (params.updates.url && !params.updates.url.startsWith('https://')) {
      throw new ValidationError('Webhook URLs must use HTTPS');
    }

    const updated = await webhookRepository.updateEndpoint(
      params.endpointId,
      params.updates
    );

    return toSafeWebhookEndpoint(updated!);
  }

  // ── Delete endpoint ───────────────────────────────────
  async deleteEndpoint(params: {
    actorUserId: string;
    endpointId: string;
    orgId: string;
  }): Promise<void> {
    await this.assertAdmin(params.orgId, params.actorUserId);
    await this.assertEndpointOwnership(params.endpointId, params.orgId);

    await webhookRepository.deleteEndpoint(params.endpointId);
    log.info({ endpointId: params.endpointId }, 'Webhook endpoint deleted');
  }

  // ── List deliveries for an endpoint ──────────────────
  async listDeliveries(params: {
    actorUserId: string;
    endpointId: string;
    orgId: string;
  }): Promise<WebhookDelivery[]> {
    await this.assertMember(params.orgId, params.actorUserId);
    await this.assertEndpointOwnership(params.endpointId, params.orgId);

    return webhookRepository.findDeliveriesByEndpoint(params.endpointId);
  }

  // ── Fanout ────────────────────────────────────────────
  // Called by auth/org services when events happen.
  // Fast — only writes delivery rows, no HTTP calls.
  // The delivery job handles the actual HTTP POSTs asynchronously.
  async fanout(params: {
    eventType: string;
    orgId: string;
    payload: Record<string, unknown>;
  }): Promise<void> {
    const { eventType, orgId, payload } = params;

    // Only active endpoints that subscribed to this event type
    const endpoints = await webhookRepository.findByOrg(orgId);
    const subscribed = endpoints.filter((ep) =>
      (ep.events as string[]).includes(eventType)
    );

    if (subscribed.length === 0) return;

    // Create a delivery row for each endpoint — parallel inserts
    await Promise.all(
      subscribed.map((ep) =>
        webhookRepository.createDelivery({
          webhookEndpointId: ep.id,
          eventType,
          payload,
        })
      )
    );

    log.info(
      { eventType, orgId, count: subscribed.length },
      'Webhook fanout queued'
    );
  }

  // ── Deliver (one delivery) ────────────────────────────
  // Makes the HTTP POST. Updates delivery record with result.
  // Called by the retry job for each due delivery.
  async deliver(deliveryId: string): Promise<void> {
    const delivery = await webhookRepository.findDeliveryById(deliveryId);

    // Shouldn't happen (job calls with IDs from findDueDeliveries),
    // but guard defensively
    if (!delivery) return;

    const endpoint = await webhookRepository.findById(
      delivery.webhookEndpointId
    );
    if (!endpoint) {
      // Endpoint was deleted mid-delivery — mark failed, stop retrying
      await webhookRepository.updateDelivery(deliveryId, { status: 'failed' });
      return;
    }

    const rawSecret = decryptSecret(endpoint.secretHash);
    const body = JSON.stringify({
      id: delivery.id,
      type: delivery.eventType,
      createdAt: delivery.createdAt,
      data: delivery.payload,
    });
    const signature = signPayload(rawSecret, body);
    const newAttempts = delivery.attempts + 1;

    try {
      const response = await fetch(endpoint.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Griffon-Signature': signature,
          'X-Griffon-Event': delivery.eventType,
          'X-Griffon-Delivery': delivery.id,
        },
        body,
        signal: AbortSignal.timeout(10_000), // 10-second timeout
      });

      if (response.ok) {
        // 2xx — success
        await webhookRepository.updateDelivery(deliveryId, {
          status: 'success',
          attempts: newAttempts,
          lastAttemptAt: new Date(),
          responseCode: response.status,
        });

        log.info(
          { deliveryId, endpointId: endpoint.id, status: response.status },
          'Webhook delivery succeeded'
        );
      } else {
        // Non-2xx — treat as failure, schedule retry or give up
        await this.scheduleRetryOrFail(
          deliveryId,
          newAttempts,
          response.status
        );

        log.warn(
          {
            deliveryId,
            endpointId: endpoint.id,
            status: response.status,
            attempts: newAttempts,
          },
          'Webhook delivery received non-2xx response'
        );
      }
    } catch (err) {
      // Network error, timeout, DNS failure, etc.
      await this.scheduleRetryOrFail(deliveryId, newAttempts, null);

      log.warn(
        { err, deliveryId, endpointId: endpoint.id, attempts: newAttempts },
        'Webhook delivery network error'
      );
    }
  }

  // ── Retry all due deliveries ──────────────────────────
  // Called by the delivery job every 30 seconds.
  // Returns number of deliveries processed.
  async retryFailed(): Promise<number> {
    const due = await webhookRepository.findDueDeliveries();

    let processed = 0;
    for (const delivery of due) {
      try {
        await this.deliver(delivery.id);
        processed++;
      } catch (err) {
        log.error(
          { err, deliveryId: delivery.id },
          'Unexpected error during delivery — skipping'
        );
      }
    }

    return processed;
  }

  // ── Send a test event to an endpoint ─────────────────
  // Useful for customers to verify their endpoint is working.
  // Creates a real delivery row so it shows up in delivery logs.
  async sendTestEvent(params: {
    actorUserId: string;
    endpointId: string;
    orgId: string;
  }): Promise<void> {
    await this.assertAdmin(params.orgId, params.actorUserId);
    await this.assertEndpointOwnership(params.endpointId, params.orgId);

    const delivery = await webhookRepository.createDelivery({
      webhookEndpointId: params.endpointId,
      eventType: 'webhook.test',
      payload: {
        message: 'This is a test event from Griffon',
        timestamp: new Date().toISOString(),
      },
    });

    // Deliver immediately (don't wait for job cycle)
    await this.deliver(delivery.id);
  }

  // ── Private helpers ───────────────────────────────────

  private async scheduleRetryOrFail(
    deliveryId: string,
    attempts: number,
    responseCode: number | null
  ): Promise<void> {
    if (attempts >= MAX_ATTEMPTS) {
      // Exhausted all retries — give up
      await webhookRepository.updateDelivery(deliveryId, {
        status: 'failed',
        attempts,
        lastAttemptAt: new Date(),
        responseCode: responseCode ?? undefined,
      });
    } else {
      // Schedule next retry using exponential backoff delay
      const delayMs = RETRY_DELAYS_MS[attempts - 1];
      const nextRetryAt = new Date(Date.now() + delayMs);
      await webhookRepository.updateDelivery(deliveryId, {
        status: 'pending',
        attempts,
        lastAttemptAt: new Date(),
        nextRetryAt,
        responseCode: responseCode ?? undefined,
      });
    }
  }
}

export const webhookService = new WebhookService();
