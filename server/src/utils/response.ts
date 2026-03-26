import { FastifyReply } from 'fastify';

// ── Types ────────────────────────────────────────────────
type SuccessResponse<T> = {
  success: true;
  data: T;
  meta?: PaginationMeta;
};

type ErrorResponse = {
  success: false;
  error: {
    code: string;
    message: string;
    details?: ValidationDetail[];
  };
};

type PaginationMeta = {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
};

type ValidationDetail = {
  field: string;
  message: string;
};

// ── Success Helpers ──────────────────────────────────────
export function sendSuccess<T>(
  reply: FastifyReply,
  data: T,
  statusCode: number = 200
) {
  const response: SuccessResponse<T> = {
    success: true,
    data,
  };
  return reply.status(statusCode).send(response);
}

export function sendCreated<T>(reply: FastifyReply, data: T) {
  return sendSuccess(reply, data, 201);
}

export function sendPaginated<T>(
  reply: FastifyReply,
  data: T[],
  meta: PaginationMeta
) {
  return reply.status(200).send({
    success: true,
    data,
    meta,
  });
}

// ── Error Helpers ────────────────────────────────────────
export function sendError(
  reply: FastifyReply,
  statusCode: number,
  code: string,
  message: string,
  details?: ValidationDetail[]
) {
  const response: ErrorResponse = {
    success: false,
    error: {
      code,
      message,
      ...(details && { details }),
    },
  };
  return reply.status(statusCode).send(response);
}

export function sendValidationError(
  reply: FastifyReply,
  details: ValidationDetail[]
) {
  return sendError(
    reply,
    400,
    'VALIDATION_ERROR',
    'Invalid request data',
    details
  );
}

export function sendNotFound(
  reply: FastifyReply,
  code: string,
  message: string
) {
  return sendError(reply, 404, code, message);
}

export function sendUnauthorized(
  reply: FastifyReply,
  code: string,
  message: string
) {
  return sendError(reply, 401, code, message);
}

export function sendForbidden(
  reply: FastifyReply,
  code: string,
  message: string
) {
  return sendError(reply, 403, code, message);
}

export function sendConflict(
  reply: FastifyReply,
  code: string,
  message: string
) {
  return sendError(reply, 409, code, message);
}

// ── Pure error object builders ────────────────────────
// Used when you need the error shape but don't have a reply object
// e.g. rate limiter, global error handler
export function buildErrorResponse(
  code: string,
  message: string,
  details?: ValidationDetail[]
): ErrorResponse {
  return {
    success: false,
    error: {
      code,
      message,
      ...(details && { details }),
    },
  };
}

export function buildSuccessResponse<T>(data: T): SuccessResponse<T> {
  return {
    success: true,
    data,
  };
}
