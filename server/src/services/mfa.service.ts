import crypto from 'crypto';
import { TOTP, Secret } from 'otpauth';
import qrcode from 'qrcode';
import { env } from '../config/env';
import { mfaRepository } from '../repositories/mfa.repository';
import { auditRepository } from '../repositories/audit.repository';
import { AuthError, NotFoundError } from '../utils/errors';
import {
  SafeMfaSetting,
  OrgMfaPolicy,
  MfaSetting,
  toSafeMfaSetting,
} from '../utils/types';
import { createLogger } from '../utils/logger';

const log = createLogger('MfaService');

// Number of recovery codes generated at enrollment and regeneration
const RECOVERY_CODE_COUNT = 8;

// TOTP window — accept ±1 step (each step = 30s) to handle clock drift.
// This means a code is valid for up to 90 seconds total.
const TOTP_WINDOW = 1;

// ── AES-256-GCM encryption helpers ───────────────────────
// TOTP secrets must be decryptable at verify time (unlike passwords).
// We encrypt at rest using MFA_ENCRYPTION_KEY — same pattern as webhook
// signing secrets in webhook.service.ts.
// Stored format: "<iv_hex>:<authTag_hex>:<ciphertext_hex>"

function encryptSecret(rawSecret: string): string {
  const key = Buffer.from(env.MFA_ENCRYPTION_KEY, 'hex');
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
  if (!ivHex || !authTagHex || !ciphertextHex) {
    throw new Error(
      `Malformed encrypted MFA secret — expected "iv:authTag:ciphertext", got ${JSON.stringify(stored)}`
    );
  }
  const key = Buffer.from(env.MFA_ENCRYPTION_KEY, 'hex');
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

// ── TOTP helpers ──────────────────────────────────────────

// Build a TOTP instance from a base32 secret string.
// Always uses SHA1/6-digit/30s — the universal authenticator app default.
function buildTotp(base32Secret: string, label: string): TOTP {
  return new TOTP({
    issuer: 'Griffon',
    label,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(base32Secret),
  });
}

// Verify a 6-digit code against a decrypted base32 secret.
// Returns true if valid within the ±1 window.
function verifyTotpCode(base32Secret: string, code: string): boolean {
  const totp = buildTotp(base32Secret, 'verify');
  const delta = totp.validate({ token: code, window: TOTP_WINDOW });
  return delta !== null;
}

// ── Recovery code helpers ─────────────────────────────────

// Generate N recovery codes in "XXXXX-XXXXX" format (10 hex chars, dash in middle).
// Returns { raw: string[], hashes: string[] } — raw goes to client once, hashes stored.
function generateRecoveryCodes(count: number): {
  raw: string[];
  hashes: string[];
} {
  const raw: string[] = [];
  const hashes: string[] = [];

  for (let i = 0; i < count; i++) {
    const code =
      crypto.randomBytes(5).toString('hex').toUpperCase() +
      '-' +
      crypto.randomBytes(5).toString('hex').toUpperCase();
    raw.push(code);
    // Use the same normalization as hashRecoveryCode so that a user entering
    // the code with or without the dash always matches the stored hash.
    hashes.push(hashRecoveryCode(code));
  }

  return { raw, hashes };
}

function hashRecoveryCode(code: string): string {
  // Normalize before hashing — strip dashes, uppercase
  // so "ABCDE-12345" and "abcde12345" hash to the same value
  const normalized = code.replace(/-/g, '').toUpperCase();
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

export class MfaService {
  // ── Setup ─────────────────────────────────────────────
  // Step 1 of enrollment. Generates a TOTP secret, encrypts and stores it
  // (with isEnabled=false), and generates 8 recovery codes.
  // Returns everything the client needs to show a QR code:
  //   - otpauthUri: scan with any authenticator app
  //   - secret: manual entry fallback (base32)
  //   - recoveryCodes: show once, user must save them
  // MFA is NOT active yet — verifySetup() must be called to confirm.
  async setupMfa(params: { userId: string; userEmail: string }): Promise<{
    otpauthUri: string;
    secret: string;
    qrCodeDataUrl: string;
    recoveryCodes: string[];
  }> {
    const { userId, userEmail } = params;

    log.info({ userId }, 'Starting MFA setup');

    // Generate a 20-byte random secret and encode as base32
    const otpauthSecret = new Secret({ size: 20 });
    const base32Secret = otpauthSecret.base32;

    // Build the TOTP instance to get the otpauth:// URI for QR codes
    const totp = buildTotp(base32Secret, userEmail);
    const otpauthUri = totp.toString();

    // Generate a QR code as a base64 PNG data URL — rendered by the frontend
    // as <img src="..."> so the user can scan it with their authenticator app.
    // Generated entirely server-side; the secret never leaves to a third party.
    const qrCodeDataUrl = await qrcode.toDataURL(otpauthUri);

    // Encrypt the base32 secret for storage
    const encryptedSecret = encryptSecret(base32Secret);

    // Upsert the setting row — resets isEnabled=false if user is re-enrolling
    await mfaRepository.createSetting(userId, encryptedSecret);

    // Generate recovery codes — delete any old ones first in case of re-enrollment
    await mfaRepository.deleteAllRecoveryCodes(userId);
    const { raw: recoveryCodes, hashes } =
      generateRecoveryCodes(RECOVERY_CODE_COUNT);
    await mfaRepository.createRecoveryCodes(userId, hashes);

    log.info({ userId }, 'MFA setup initiated — awaiting verification');

    return { otpauthUri, secret: base32Secret, qrCodeDataUrl, recoveryCodes };
  }

  // ── Verify Setup ──────────────────────────────────────
  // Step 2 of enrollment. User submits their first TOTP code to prove
  // their authenticator app is correctly configured.
  // On success, isEnabled flips to true and MFA is active on next login.
  async verifySetup(params: {
    userId: string;
    code: string;
    ipAddress?: string;
  }): Promise<SafeMfaSetting> {
    const { userId, code, ipAddress } = params;

    const setting = await mfaRepository.findByUserId(userId);
    if (!setting) {
      throw new NotFoundError(
        'MFA_NOT_SETUP',
        'MFA setup has not been started. Call POST /auth/mfa/setup first.'
      );
    }

    if (setting.isEnabled) {
      throw new AuthError(
        'MFA_ALREADY_ENABLED',
        'MFA is already enabled on this account.',
        400
      );
    }

    const base32Secret = decryptSecret(setting.encryptedSecret);
    if (!verifyTotpCode(base32Secret, code)) {
      throw new AuthError(
        'MFA_INVALID_CODE',
        'Invalid verification code. Please check your authenticator app and try again.',
        400
      );
    }

    await mfaRepository.enable(userId);

    void auditRepository.create({
      userId,
      eventType: 'mfa_enrolled',
      ipAddress,
      metadata: {},
    });

    log.info({ userId }, 'MFA enrolled successfully');

    // Re-fetch to return the updated row (isEnabled=true, enabledAt set)
    const updated = await mfaRepository.findByUserId(userId);
    if (!updated) {
      throw new Error(
        `MFA setting disappeared for user ${userId} immediately after enable — this should not happen`
      );
    }
    return toSafeMfaSetting(updated);
  }

  // ── Verify Code (login step 2) ────────────────────────
  // Called from auth.service after mfaToken is validated.
  // Accepts either a 6-digit TOTP code or a recovery code.
  // Returns true on success — auth.service issues the real tokens.
  async verifyLoginCode(params: {
    userId: string;
    code: string;
    ipAddress?: string;
  }): Promise<void> {
    const { userId, code, ipAddress } = params;

    const setting = await mfaRepository.findByUserId(userId);
    if (!setting?.isEnabled) {
      // Should not happen — login flow checks MFA before calling this
      throw new AuthError(
        'MFA_NOT_ENABLED',
        'MFA is not enabled for this account.'
      );
    }

    const base32Secret = decryptSecret(setting.encryptedSecret);

    // Try TOTP first
    if (verifyTotpCode(base32Secret, code)) {
      void auditRepository.create({
        userId,
        eventType: 'mfa_verified',
        ipAddress,
        metadata: {},
      });
      return;
    }

    // Try recovery code — hash and look up
    const codeHash = hashRecoveryCode(code);
    const recoveryCode = await mfaRepository.findRecoveryCode(userId, codeHash);

    if (recoveryCode) {
      // Delete immediately — single use
      await mfaRepository.deleteRecoveryCode(recoveryCode.id);

      void auditRepository.create({
        userId,
        eventType: 'mfa_recovery_used',
        ipAddress,
        metadata: {},
      });

      log.warn({ userId }, 'MFA recovery code used');
      return;
    }

    throw new AuthError(
      'MFA_INVALID_CODE',
      'Invalid code. Please check your authenticator app or use a recovery code.',
      400
    );
  }

  // ── Disable MFA ───────────────────────────────────────
  // Requires the user to prove they still control their authenticator
  // before disabling — prevents an attacker with a stolen session from
  // silently removing MFA.
  async disableMfa(params: {
    userId: string;
    code: string;
    ipAddress?: string;
  }): Promise<void> {
    const { userId, code, ipAddress } = params;

    await this.assertTotpCode(userId, code);

    // deleteSetting cascades to recovery codes via FK
    await mfaRepository.deleteSetting(userId);

    void auditRepository.create({
      userId,
      eventType: 'mfa_disabled',
      ipAddress,
      metadata: {},
    });

    log.info({ userId }, 'MFA disabled');
  }

  // ── Regenerate Recovery Codes ─────────────────────────
  // Replaces all existing recovery codes with a fresh set.
  // Requires a valid TOTP code — same guard as disableMfa.
  async regenerateRecoveryCodes(params: {
    userId: string;
    code: string;
    ipAddress?: string;
  }): Promise<string[]> {
    const { userId, code, ipAddress } = params;

    await this.assertTotpCode(userId, code);

    await mfaRepository.deleteAllRecoveryCodes(userId);
    const { raw, hashes } = generateRecoveryCodes(RECOVERY_CODE_COUNT);
    await mfaRepository.createRecoveryCodes(userId, hashes);

    void auditRepository.create({
      userId,
      eventType: 'mfa_recovery_regenerated',
      ipAddress,
      metadata: {},
    });

    log.info({ userId }, 'Recovery codes regenerated');

    return raw;
  }

  // ── Status ────────────────────────────────────────────
  // Returns whether MFA is enrolled and how many recovery codes remain.
  async getStatus(userId: string): Promise<{
    enabled: boolean;
    enabledAt: Date | null;
    recoveryCodesRemaining: number;
  }> {
    const setting = await mfaRepository.findByUserId(userId);

    if (!setting?.isEnabled) {
      return { enabled: false, enabledAt: null, recoveryCodesRemaining: 0 };
    }

    const recoveryCodesRemaining =
      await mfaRepository.countRecoveryCodes(userId);

    return {
      enabled: true,
      enabledAt: setting.enabledAt,
      recoveryCodesRemaining,
    };
  }

  // ── Admin: force-disable ──────────────────────────────
  // Admin bypass — does not require a TOTP code.
  // Used when a user loses access to their authenticator and contacts support.
  async adminDisableMfa(params: {
    targetUserId: string;
    adminId: string;
    ipAddress?: string;
  }): Promise<void> {
    const { targetUserId, adminId, ipAddress } = params;

    const setting = await mfaRepository.findByUserId(targetUserId);
    if (!setting?.isEnabled) {
      throw new NotFoundError(
        'MFA_NOT_ENABLED',
        'MFA is not enabled for this user.'
      );
    }

    await mfaRepository.deleteSetting(targetUserId);

    void auditRepository.create({
      userId: adminId,
      eventType: 'mfa_disabled',
      ipAddress,
      metadata: { targetUserId, disabledBy: 'admin' },
    });

    log.warn({ targetUserId, adminId }, 'MFA force-disabled by admin');
  }

  // ── Org MFA Policy ────────────────────────────────────

  // Check if an org requires MFA for all members.
  // Returns false when no policy row exists (same as requireMfa=false).
  async isOrgMfaEnforced(orgId: string): Promise<boolean> {
    const policy = await mfaRepository.findOrgPolicy(orgId);
    return policy?.requireMfa ?? false;
  }

  // Enable or disable MFA enforcement for an org.
  async setOrgMfaPolicy(params: {
    orgId: string;
    requireMfa: boolean;
    actorUserId: string;
    ipAddress?: string;
  }): Promise<OrgMfaPolicy> {
    const { orgId, requireMfa, actorUserId, ipAddress } = params;

    const policy = await mfaRepository.upsertOrgPolicy(orgId, requireMfa);

    void auditRepository.create({
      userId: actorUserId,
      eventType: requireMfa ? 'org_mfa_enforced' : 'org_mfa_unenforced',
      ipAddress,
      metadata: { orgId },
    });

    log.info({ orgId, requireMfa, actorUserId }, 'Org MFA policy updated');

    return policy;
  }

  // Verify a TOTP code for a user — used by disableMfa, regenerateRecoveryCodes,
  // and api-key.service's MFA gate. Does NOT accept recovery codes.
  // Pass a pre-fetched setting to avoid a redundant DB round-trip.
  async assertTotpCode(
    userId: string,
    code: string,
    prefetchedSetting?: MfaSetting | null
  ): Promise<void> {
    const setting =
      prefetchedSetting ?? (await mfaRepository.findByUserId(userId));

    if (!setting?.isEnabled) {
      throw new NotFoundError(
        'MFA_NOT_ENABLED',
        'MFA is not enabled on this account.'
      );
    }

    const base32Secret = decryptSecret(setting.encryptedSecret);
    if (!verifyTotpCode(base32Secret, code)) {
      throw new AuthError('MFA_INVALID_CODE', 'Invalid TOTP code.', 400);
    }
  }

  // Check if a user has MFA enabled — used by auth.service in the login flow.
  async isMfaEnabled(userId: string): Promise<boolean> {
    const setting = await mfaRepository.findByUserId(userId);
    return setting?.isEnabled ?? false;
  }

  // Check if a user satisfies an org's MFA requirement.
  // Returns true if: org doesn't enforce MFA, or user has MFA enabled.
  async userSatisfiesOrgMfaPolicy(
    userId: string,
    orgId: string
  ): Promise<boolean> {
    const enforced = await this.isOrgMfaEnforced(orgId);
    if (!enforced) return true;

    return this.isMfaEnabled(userId);
  }
}

export const mfaService = new MfaService();
