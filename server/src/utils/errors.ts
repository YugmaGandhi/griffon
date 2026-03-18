export class AppError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode: number = 500
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export class ValidationError extends AppError {
  constructor(
    message: string,
    public readonly details?: { field: string; message: string }[]
  ) {
    super('VALIDATION_ERROR', message, 400);
    this.name = 'ValidationError';
  }
}

export class ConflictError extends AppError {
  constructor(code: string, message: string) {
    super(code, message, 409);
    this.name = 'ConflictError';
  }
}

export class AuthError extends AppError {
  constructor(code: string, message: string, statusCode: number = 401) {
    super(code, message, statusCode);
    this.name = 'AuthError';
  }
}

export class NotFoundError extends AppError {
  constructor(code: string, message: string) {
    super(code, message, 404);
    this.name = 'NotFoundError';
  }
}

export class ForbiddenError extends AppError {
  constructor(code: string, message: string) {
    super(code, message, 403);
    this.name = 'ForbiddenError';
  }
}

// Type guard — lets TypeScript know if an unknown error is AppError
export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}
