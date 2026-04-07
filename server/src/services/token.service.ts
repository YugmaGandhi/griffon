import { SignJWT, jwtVerify } from 'jose';
import crypto from 'crypto';
import { env } from '../config/env';
import { TokenUser } from '../utils/types';
import { createLogger } from '../utils/logger';

const log = createLogger('TokenService');

// Decode base64 keys from env into buffers jose can use
function getPrivateKey() {
  const pem = Buffer.from(env.JWT_PRIVATE_KEY, 'base64').toString('utf-8');
  return crypto.createPrivateKey(pem);
}

function getPublicKey() {
  const pem = Buffer.from(env.JWT_PUBLIC_KEY, 'base64').toString('utf-8');
  return crypto.createPublicKey(pem);
}

export type AccessTokenPayload = {
  sub: string; // userId
  email: string;
  roles: string[];
  permissions: string[];
  orgId: string | null;
  orgRole: string | null;
  orgPermissions: string[];
  iat: number; // issued at
  exp: number; // expires at
  iss: string; // issuer
};

export class TokenService {
  // ── Generate Access Token (JWT) ───────────────────────
  async generateAccessToken(user: TokenUser): Promise<string> {
    log.debug({ userId: user.id }, 'Generating access token');

    const privateKey = getPrivateKey();

    const token = await new SignJWT({
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
      orgId: user.orgId,
      orgRole: user.orgRole,
      orgPermissions: user.orgPermissions,
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setSubject(user.id)
      .setIssuer(env.JWT_ISSUER)
      .setIssuedAt()
      .setExpirationTime(env.JWT_ACCESS_EXPIRY)
      .sign(privateKey);

    return token;
  }

  // ── Verify Access Token ───────────────────────────────
  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    log.debug('Verifying access token');

    const publicKey = getPublicKey();

    try {
      const { payload } = await jwtVerify(token, publicKey, {
        issuer: env.JWT_ISSUER,
        algorithms: ['RS256'],
      });

      return payload as unknown as AccessTokenPayload;
    } catch (err) {
      log.debug({ err }, 'Access token verification failed');
      throw err;
    }
  }

  // ── Generate Refresh Token ────────────────────────────
  // Cryptographically random — NOT a JWT
  // Stored as hash in DB, raw value sent to client
  generateRefreshToken(): string {
    return crypto.randomBytes(64).toString('base64url');
  }

  // ── Hash Refresh Token ────────────────────────────────
  // We store the HASH in DB, never the raw token
  // SHA-256 — deterministic, same input always same output
  // Safe for tokens because tokens are already 64 random bytes
  // Never use this for passwords — use Argon2id for passwords
  hashRefreshToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  // ── Get Refresh Token Expiry Date ─────────────────────
  getRefreshTokenExpiry(): Date {
    const days = parseInt(env.JWT_REFRESH_EXPIRY.replace('d', ''), 10);
    const expiry = new Date();
    expiry.setDate(expiry.getDate() + days);
    return expiry;
  }
}

export const tokenService = new TokenService();
