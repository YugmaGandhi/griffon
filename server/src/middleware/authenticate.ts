import { FastifyRequest, FastifyReply } from 'fastify';
import { tokenService } from '../services/token.service';
import { sendUnauthorized } from '../utils/response';
import { createLogger } from '../utils/logger';

const log = createLogger('AuthMiddleware');

// Extend FastifyRequest to include the user property
// This gives type safety when accessing req.user in route handlers
declare module 'fastify' {
  interface FastifyRequest {
    user?: {
      id: string;
      email: string;
      roles: string[];
      permissions: string[];
      orgId: string | null;
      orgRole: string | null;
      orgPermissions: string[];
    };
  }
}

export async function authenticate(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const authHeader = request.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    log.debug({ reqId: request.id }, 'Missing or invalid authorization header');
    return sendUnauthorized(reply, 'MISSING_TOKEN', 'Authentication required');
  }

  const token = authHeader.slice(7); // Remove 'Bearer ' prefix

  try {
    const payload = await tokenService.verifyAccessToken(token);

    // Attach decoded user to request — available in all route handlers
    request.user = {
      id: payload.sub,
      email: payload.email,
      roles: payload.roles,
      permissions: payload.permissions,
      orgId: payload.orgId ?? null,
      orgRole: payload.orgRole ?? null,
      orgPermissions: payload.orgPermissions ?? [],
    };
  } catch (err) {
    log.debug({ reqId: request.id, err }, 'Token verification failed');

    const message =
      err instanceof Error && err.message.includes('expired')
        ? 'Your session has expired. Please log in again.'
        : 'Invalid authentication token';

    const code =
      err instanceof Error && err.message.includes('expired')
        ? 'TOKEN_EXPIRED'
        : 'TOKEN_INVALID';

    return sendUnauthorized(reply, code, message);
  }
}
