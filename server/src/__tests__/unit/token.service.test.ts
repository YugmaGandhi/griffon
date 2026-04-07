import { TokenService } from '../../services/token.service';
import { TokenUser } from '../../utils/types';

const tokenService = new TokenService();

const mockUser: TokenUser = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  email: 'test@example.com',
  roles: ['user'],
  permissions: ['read:profile'],
  orgId: null,
  orgRole: null,
  orgPermissions: [],
};

describe('TokenService', () => {
  describe('generateAccessToken()', () => {
    it('should return a JWT string', async () => {
      const token = await tokenService.generateAccessToken(mockUser);

      expect(typeof token).toBe('string');
      // JWTs have exactly 3 parts separated by dots
      expect(token.split('.')).toHaveLength(3);
    });

    it('should produce tokens with valid structure', async () => {
      const token = await tokenService.generateAccessToken(mockUser);
      const parts = token.split('.');

      // Header, payload, signature — all must be present
      expect(parts).toHaveLength(3);
      expect(parts[0].length).toBeGreaterThan(0); // header
      expect(parts[1].length).toBeGreaterThan(0); // payload
      expect(parts[2].length).toBeGreaterThan(0); // signature
    });
  });

  describe('verifyAccessToken()', () => {
    it('should verify a valid token and return payload', async () => {
      const token = await tokenService.generateAccessToken(mockUser);
      const payload = await tokenService.verifyAccessToken(token);

      expect(payload.sub).toBe(mockUser.id);
      expect(payload.email).toBe(mockUser.email);
      expect(payload.roles).toEqual(mockUser.roles);
      expect(payload.permissions).toEqual(mockUser.permissions);
    });

    it('should throw on invalid token', async () => {
      await expect(
        tokenService.verifyAccessToken('invalid.token.here')
      ).rejects.toThrow();
    });

    it('should throw on tampered token', async () => {
      const token = await tokenService.generateAccessToken(mockUser);

      // Tamper with the payload section (middle part)
      const parts = token.split('.');
      parts[1] = Buffer.from(
        JSON.stringify({ sub: 'hacker', email: 'hacker@evil.com' })
      ).toString('base64url');
      const tampered = parts.join('.');

      await expect(tokenService.verifyAccessToken(tampered)).rejects.toThrow();
    });
  });

  describe('generateRefreshToken()', () => {
    it('should return a non-empty string', () => {
      const token = tokenService.generateRefreshToken();
      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(0);
    });

    it('should generate unique tokens each time', () => {
      const token1 = tokenService.generateRefreshToken();
      const token2 = tokenService.generateRefreshToken();
      expect(token1).not.toBe(token2);
    });

    it('should be URL safe (base64url)', () => {
      const token = tokenService.generateRefreshToken();
      // base64url uses only A-Z, a-z, 0-9, -, _
      expect(token).toMatch(/^[A-Za-z0-9\-_]+$/);
    });
  });

  describe('hashRefreshToken()', () => {
    it('should return a hex string', () => {
      const token = tokenService.generateRefreshToken();
      const hash = tokenService.hashRefreshToken(token);

      expect(typeof hash).toBe('string');
      expect(hash).toMatch(/^[a-f0-9]{64}$/); // SHA-256 = 64 hex chars
    });

    it('should be deterministic — same input always same output', () => {
      const token = tokenService.generateRefreshToken();
      const hash1 = tokenService.hashRefreshToken(token);
      const hash2 = tokenService.hashRefreshToken(token);

      // Unlike Argon2id, SHA-256 produces the same hash every time
      // This is what allows DB lookup by hash
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different tokens', () => {
      const token1 = tokenService.generateRefreshToken();
      const token2 = tokenService.generateRefreshToken();

      expect(tokenService.hashRefreshToken(token1)).not.toBe(
        tokenService.hashRefreshToken(token2)
      );
    });
  });

  describe('getRefreshTokenExpiry()', () => {
    it('should return a future date', () => {
      const expiry = tokenService.getRefreshTokenExpiry();
      expect(expiry.getTime()).toBeGreaterThan(Date.now());
    });

    it('should be approximately 30 days from now', () => {
      const expiry = tokenService.getRefreshTokenExpiry();
      const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
      const diff = expiry.getTime() - Date.now();

      // Within 1 minute of 30 days
      expect(diff).toBeGreaterThan(thirtyDaysMs - 60000);
      expect(diff).toBeLessThan(thirtyDaysMs + 60000);
    });
  });
});
