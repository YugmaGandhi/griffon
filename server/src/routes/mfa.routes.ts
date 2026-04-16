import { FastifyInstance, FastifyPluginCallback } from 'fastify';
import { z } from 'zod';
import { mfaService } from '../services/mfa.service';
import { authService } from '../services/auth.service';
import { isAppError } from '../utils/errors';
import { createLogger } from '../utils/logger';
import {
  sendSuccess,
  sendCreated,
  sendError,
  sendValidationError,
} from '../utils/response';
import { authenticate } from '../middleware/authenticate';

const log = createLogger('MfaRoutes');

// ── Schemas ───────────────────────────────────────────────

// Shared schema for any request that requires a 6-digit TOTP code.
// Used by verify-setup, disable MFA, and regenerate recovery codes.
const totpCodeSchema = z.object({
  code: z
    .string()
    .length(6, 'TOTP code must be exactly 6 digits')
    .regex(/^\d{6}$/, 'TOTP code must be numeric'),
});

const verifyLoginSchema = z.object({
  mfaToken: z.string().min(1, 'MFA token is required'),
  code: z.string().min(1, 'Code is required'),
});

// ── Routes ────────────────────────────────────────────────

const mfaRoutes: FastifyPluginCallback = (
  app: FastifyInstance,
  _options,
  done
) => {
  // ── POST /auth/mfa/setup — Start MFA enrollment ────────
  // Step 1: generates a TOTP secret, stores it (not yet enabled),
  // and returns an otpauth:// URI for QR scanning + 8 recovery codes.
  // Recovery codes are shown exactly once — the user must save them now.
  app.post(
    '/mfa/setup',
    { preHandler: [authenticate] },
    async (request, reply) => {
      try {
        const result = await mfaService.setupMfa({
          userId: request.user!.id,
          userEmail: request.user!.email,
        });

        log.info({ userId: request.user!.id }, 'MFA setup initiated');
        return sendCreated(reply, result);
      } catch (err) {
        if (isAppError(err)) {
          return sendError(reply, err.statusCode, err.code, err.message);
        }
        log.error({ err, reqId: request.id }, 'Unexpected error in MFA setup');
        throw err;
      }
    }
  );

  // ── POST /auth/mfa/verify-setup — Confirm enrollment ───
  // Step 2: user submits their first 6-digit TOTP code to prove their
  // authenticator app is correctly configured. Flips isEnabled → true.
  app.post(
    '/mfa/verify-setup',
    { preHandler: [authenticate] },
    async (request, reply) => {
      const parsed = totpCodeSchema.safeParse(request.body);
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
        const setting = await mfaService.verifySetup({
          userId: request.user!.id,
          code: parsed.data.code,
          ipAddress: request.ip,
        });

        log.info({ userId: request.user!.id }, 'MFA enrollment confirmed');
        return sendSuccess(reply, { mfa: setting });
      } catch (err) {
        if (isAppError(err)) {
          return sendError(reply, err.statusCode, err.code, err.message);
        }
        log.error(
          { err, reqId: request.id },
          'Unexpected error confirming MFA setup'
        );
        throw err;
      }
    }
  );

  // ── POST /auth/mfa/verify — Login step 2 ───────────────
  // Called after a successful credentials login returned mfaRequired: true.
  // The client submits the short-lived mfaToken alongside a 6-digit TOTP
  // code (or recovery code). On success returns full tokens — same shape
  // as a normal login response.
  // NOTE: No authenticate middleware — the user has mfaToken, not accessToken.
  app.post('/mfa/verify', async (request, reply) => {
    const parsed = verifyLoginSchema.safeParse(request.body);
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
      const result = await authService.verifyMfaAndLogin({
        mfaToken: parsed.data.mfaToken,
        code: parsed.data.code,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      });

      return sendSuccess(reply, result);
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      log.error(
        { err, reqId: request.id },
        'Unexpected error verifying MFA login code'
      );
      throw err;
    }
  });

  // ── GET /auth/mfa/status — Get MFA status ─────────────
  // Returns whether MFA is enrolled and how many recovery codes remain.
  app.get(
    '/mfa/status',
    { preHandler: [authenticate] },
    async (request, reply) => {
      try {
        const status = await mfaService.getStatus(request.user!.id);
        return sendSuccess(reply, { mfa: status });
      } catch (err) {
        if (isAppError(err)) {
          return sendError(reply, err.statusCode, err.code, err.message);
        }
        log.error(
          { err, reqId: request.id },
          'Unexpected error fetching MFA status'
        );
        throw err;
      }
    }
  );

  // ── DELETE /auth/mfa — Disable MFA ────────────────────
  // Requires a valid TOTP code to prevent a stolen session from silently
  // removing MFA protection. Deletes the setting and all recovery codes.
  app.delete('/mfa', { preHandler: [authenticate] }, async (request, reply) => {
    const parsed = totpCodeSchema.safeParse(request.body);
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
      await mfaService.disableMfa({
        userId: request.user!.id,
        code: parsed.data.code,
        ipAddress: request.ip,
      });

      log.info({ userId: request.user!.id }, 'MFA disabled by user');
      return sendSuccess(reply, { message: 'MFA disabled successfully' });
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      log.error({ err, reqId: request.id }, 'Unexpected error disabling MFA');
      throw err;
    }
  });

  // ── POST /auth/mfa/recovery-codes — Regenerate codes ──
  // Replaces all existing recovery codes with a fresh set of 8.
  // Requires a valid TOTP code — same guard as disabling MFA.
  app.post(
    '/mfa/recovery-codes',
    { preHandler: [authenticate] },
    async (request, reply) => {
      const parsed = totpCodeSchema.safeParse(request.body);
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
        const recoveryCodes = await mfaService.regenerateRecoveryCodes({
          userId: request.user!.id,
          code: parsed.data.code,
          ipAddress: request.ip,
        });

        log.info(
          { userId: request.user!.id },
          'MFA recovery codes regenerated'
        );
        return sendSuccess(reply, { recoveryCodes });
      } catch (err) {
        if (isAppError(err)) {
          return sendError(reply, err.statusCode, err.code, err.message);
        }
        log.error(
          { err, reqId: request.id },
          'Unexpected error regenerating recovery codes'
        );
        throw err;
      }
    }
  );

  done();
};

export { mfaRoutes };
