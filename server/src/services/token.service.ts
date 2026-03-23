import { SignJWT, jwtVerify } from 'jose';
import crypto from 'crypto';
import argon2 from 'argon2';
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
  // Same principle as password hashing
  async hashRefreshToken(token: string): Promise<string> {
    return argon2.hash(token, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });
  }

  // ── Verify Refresh Token ──────────────────────────────
  async verifyRefreshToken(token: string, hash: string): Promise<boolean> {
    if (!hash.startsWith('$argon2')) return false;

    try {
      return await argon2.verify(hash, token);
    } catch {
      return false;
    }
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
