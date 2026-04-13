import { GriffonConfig, LoginResult, RegisterResult, AuthUser, ApiResponse, ApiErrorResponse, TokenPair } from './types'
import { GriffonError } from './errors'
import { TokenStore } from './token-store'
import { API_PATHS } from './api-paths'

export class GriffonClient {
  private config: Required<GriffonConfig>
  private tokenStore: TokenStore
  private refreshPromise: Promise<void> | null = null

  constructor(config: GriffonConfig) {
    this.config = {
      timeout: 10000,
      fetchImpl: fetch,
      ...config,
    }
    this.tokenStore = new TokenStore()
  }

  // ── Auth Methods ──────────────────────────────────────

  async register(email: string, password: string): Promise<RegisterResult> {
    const response = await this.request<RegisterResult>(
      'POST',
      API_PATHS.auth.register,
      { email, password }
    )
    return response
  }

  async login(email: string, password: string): Promise<LoginResult> {
    const result = await this.request<LoginResult>(
      'POST',
      API_PATHS.auth.login,
      { email, password }
    )

    // Store tokens after successful login
    this.tokenStore.set({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      expiresIn: result.expiresIn,
    })

    return result
  }

  async logout(): Promise<void> {
    const refreshToken = this.tokenStore.getRefreshToken()

    if (refreshToken) {
      try {
        await this.request('POST', API_PATHS.auth.logout, { refreshToken })
      } catch {
        // Even if server logout fails — clear local tokens
      }
    }

    this.tokenStore.clear()
  }

  async getMe(): Promise<AuthUser> {
    return this.authenticatedRequest<AuthUser>('GET', API_PATHS.auth.me)
  }

  async refreshTokens(): Promise<void> {
    const refreshToken = this.tokenStore.getRefreshToken()
    if (!refreshToken) {
      throw new GriffonError(
        'NOT_AUTHENTICATED',
        'No refresh token available',
        401
      )
    }

    const result = await this.request<TokenPair>(
      'POST',
      API_PATHS.auth.refresh,
      { refreshToken }
    )

    this.tokenStore.set(result)
  }

  async forgotPassword(email: string): Promise<{ message: string }> {
    return this.request('POST', API_PATHS.auth.forgotPassword, { email })
  }

  async resetPassword(
    token: string,
    newPassword: string
  ): Promise<{ message: string }> {
    return this.request('POST', API_PATHS.auth.resetPassword, {
      token,
      newPassword,
    })
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    return this.request('GET', `${API_PATHS.auth.verifyEmail}?token=${token}`)
  }

  // ── OAuth Methods ─────────────────────────────────────

  // Returns the URL to redirect the user to for OAuth login
  getOAuthUrl(provider: string): string {
    return `${this.config.baseUrl}${API_PATHS.oauth.provider(provider)}`
  }

  // Call this after OAuth redirect returns tokens in URL params
  handleOAuthCallback(accessToken: string, refreshToken: string): void {
    this.tokenStore.set({
      accessToken,
      refreshToken,
      expiresIn: 900,
    })
  }

  // ── Token Methods ─────────────────────────────────────

  isAuthenticated(): boolean {
    return this.tokenStore.isAuthenticated()
  }

  getAccessToken(): string | null {
    return this.tokenStore.getAccessToken()
  }

  // ── Private Request Methods ───────────────────────────

  // Makes an authenticated request
  // Automatically refreshes token if expired
  private async authenticatedRequest<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    // If access token is expired — refresh before making request
    if (!this.tokenStore.isAccessTokenValid()) {
      await this.ensureTokenRefreshed()
    }

    const accessToken = this.tokenStore.getAccessToken()
    if (!accessToken) {
      throw new GriffonError(
        'NOT_AUTHENTICATED',
        'Not authenticated',
        401
      )
    }

    return this.request<T>(method, path, body, {
      Authorization: `Bearer ${accessToken}`,
    })
  }

  // Ensures token refresh only happens once even if
  // multiple requests fire simultaneously
  private async ensureTokenRefreshed(): Promise<void> {
    if (!this.refreshPromise) {
      this.refreshPromise = this.refreshTokens().finally(() => {
        this.refreshPromise = null
      })
    }
    await this.refreshPromise
  }

  // Base request method
  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders?: Record<string, string>
  ): Promise<T> {
    const url = `${this.config.baseUrl}${path}`

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...extraHeaders,
    }

    const controller = new AbortController()
    const timeout = setTimeout(
      () => controller.abort(),
      this.config.timeout
    )

    try {
      const response = await this.config.fetchImpl(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      })

      const json = await response.json() as
        | ApiResponse<T>
        | ApiErrorResponse

      if (!response.ok || !json.success) {
        const error = json as ApiErrorResponse
        throw new GriffonError(
          error.error.code,
          error.error.message,
          response.status,
          error.error.details
        )
      }

      return (json as ApiResponse<T>).data
    } catch (err) {
      if (err instanceof GriffonError) throw err

      if (err instanceof Error && err.name === 'AbortError') {
        throw new GriffonError(
          'REQUEST_TIMEOUT',
          'Request timed out',
          408
        )
      }

      throw new GriffonError(
        'NETWORK_ERROR',
        'Network request failed',
        0
      )
    } finally {
      clearTimeout(timeout)
    }
  }
}