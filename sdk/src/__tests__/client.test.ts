import { GriffonClient } from '../client'
import { GriffonError } from '../errors'
import { API_PATHS } from '../api-paths'

// Mock fetch globally — no real HTTP calls ever made
const mockFetch = jest.fn()

const createClient = () =>
  new GriffonClient({
    baseUrl: 'http://mock-server.test',
    fetchImpl: mockFetch as unknown as typeof fetch,
  })

// Helper — mock a successful API response
function mockSuccess<T>(data: T, status = 200) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status,
    json: async () => ({ success: true, data }),
  })
}

// Helper — mock a failed API response
function mockError(code: string, message: string, status: number) {
  mockFetch.mockResolvedValueOnce({
    ok: false,
    status,
    json: async () => ({
      success: false,
      error: { code, message },
    }),
  })
}

describe('GriffonClient', () => {
  beforeEach(() => {
    mockFetch.mockClear()
  })

  describe('register()', () => {
    it('should call register endpoint with correct payload', async () => {
      const client = createClient()

      mockSuccess({
        user: { id: 'uuid', email: 'test@example.com', isVerified: false, createdAt: '' },
        message: 'Account created successfully',
      }, 201)

      const result = await client.register('test@example.com', 'password123')

      expect(mockFetch).toHaveBeenCalledWith(
        `http://mock-server.test${API_PATHS.auth.register}`,
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ email: 'test@example.com', password: 'password123' }),
        })
      )
      expect(result.message).toContain('Account created')
    })

    it('should throw GriffonError on duplicate email', async () => {
      const client = createClient()

      mockError('EMAIL_ALREADY_EXISTS', 'An account with this email already exists', 409)

      await expect(
        client.register('existing@example.com', 'password123')
      ).rejects.toThrow(GriffonError)
    })
  })

  describe('login()', () => {
    const mockLoginResponse = {
      accessToken: 'mock.jwt.token',
      refreshToken: 'mock-refresh-token',
      expiresIn: 900,
      user: {
        id: 'uuid',
        email: 'test@example.com',
        isVerified: true,
        roles: ['user'],
        permissions: ['read:profile'],
        createdAt: '',
        updatedAt: '',
      },
    }

    it('should store tokens after successful login', async () => {
      const client = createClient()
      mockSuccess(mockLoginResponse)

      await client.login('test@example.com', 'password123')

      expect(client.isAuthenticated()).toBe(true)
      expect(client.getAccessToken()).toBe('mock.jwt.token')
    })

    it('should throw GriffonError on invalid credentials', async () => {
      const client = createClient()
      mockError('INVALID_CREDENTIALS', 'Invalid email or password', 401)

      await expect(
        client.login('test@example.com', 'wrongpassword')
      ).rejects.toThrow(GriffonError)

      expect(client.isAuthenticated()).toBe(false)
    })

    it('should call correct endpoint', async () => {
      const client = createClient()
      mockSuccess(mockLoginResponse)

      await client.login('test@example.com', 'password123')

      expect(mockFetch).toHaveBeenCalledWith(
        `http://mock-server.test${API_PATHS.auth.login}`,
        expect.objectContaining({ method: 'POST' })
      )
    })
  })

  describe('logout()', () => {
    it('should clear tokens after logout', async () => {
      const client = createClient()

      // Login first
      mockSuccess({
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresIn: 900,
        user: { id: 'uuid', email: 'test@example.com', isVerified: true, roles: [], permissions: [], createdAt: '', updatedAt: '' },
      })
      await client.login('test@example.com', 'password123')
      expect(client.isAuthenticated()).toBe(true)

      // Logout
      mockSuccess({ message: 'Logged out successfully' })
      await client.logout()

      expect(client.isAuthenticated()).toBe(false)
      expect(client.getAccessToken()).toBeNull()
    })

    it('should clear tokens even if server logout fails', async () => {
      const client = createClient()

      mockSuccess({
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresIn: 900,
        user: { id: 'uuid', email: 'test@example.com', isVerified: true, roles: [], permissions: [], createdAt: '', updatedAt: '' },
      })
      await client.login('test@example.com', 'password123')

      // Server logout fails
      mockError('INTERNAL_ERROR', 'Server error', 500)
      await client.logout()

      // Tokens still cleared locally
      expect(client.isAuthenticated()).toBe(false)
    })
  })

  describe('getMe()', () => {
    it('should attach bearer token to request', async () => {
      const client = createClient()

      // Login
      mockSuccess({
        accessToken: 'my.jwt.token',
        refreshToken: 'refresh',
        expiresIn: 900,
        user: { id: 'uuid', email: 'test@example.com', isVerified: true, roles: [], permissions: [], createdAt: '', updatedAt: '' },
      })
      await client.login('test@example.com', 'password123')

      // GetMe
      mockSuccess({
        user: { id: 'uuid', email: 'test@example.com', isVerified: true, roles: ['user'], permissions: ['read:profile'], createdAt: '', updatedAt: '' },
      })
      await client.getMe()

      expect(mockFetch).toHaveBeenLastCalledWith(
        `http://mock-server.test${API_PATHS.auth.me}`,
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer my.jwt.token',
          }),
        })
      )
    })

    it('should throw when not authenticated', async () => {
      const client = createClient()

      await expect(client.getMe()).rejects.toThrow(GriffonError)
      expect(mockFetch).not.toHaveBeenCalled()
    })
  })

  describe('GriffonError', () => {
    it('should have correct properties', async () => {
      const client = createClient()
      mockError('INVALID_CREDENTIALS', 'Invalid email or password', 401)

      try {
        await client.login('test@example.com', 'wrong')
      } catch (err) {
        expect(err).toBeInstanceOf(GriffonError)
        if (err instanceof GriffonError) {
          expect(err.code).toBe('INVALID_CREDENTIALS')
          expect(err.statusCode).toBe(401)
          expect(err.isUnauthorized).toBe(true)
          expect(err.isTokenExpired).toBe(false)
        }
      }
    })
  })

  describe('getOAuthUrl()', () => {
    it('should return correct OAuth URL', () => {
      const client = createClient()
      const url = client.getOAuthUrl('google')
      expect(url).toBe('http://mock-server.test/auth/oauth/google')
    })
  })
})