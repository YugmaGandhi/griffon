export class GriffonError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode: number,
    public readonly details?: { field: string; message: string }[]
  ) {
    super(message)
    this.name = 'GriffonError'

    // Fix prototype chain for instanceof checks
    Object.setPrototypeOf(this, GriffonError.prototype)
  }

  // Check if error is a specific code
  is(code: string): boolean {
    return this.code === code
  }

  // Common error type checks
  get isUnauthorized(): boolean {
    return this.statusCode === 401
  }

  get isForbidden(): boolean {
    return this.statusCode === 403
  }

  get isValidationError(): boolean {
    return this.code === 'VALIDATION_ERROR'
  }

  get isRateLimited(): boolean {
    return this.code === 'RATE_LIMIT_EXCEEDED'
  }

  get isTokenExpired(): boolean {
    return this.code === 'TOKEN_EXPIRED'
  }
}