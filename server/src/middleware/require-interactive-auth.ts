import { FastifyRequest, FastifyReply } from 'fastify';
import { sendForbidden } from '../utils/response';
import { createLogger } from '../utils/logger';

const log = createLogger('RequireInteractiveAuth');

// Blocks API-key principals from reaching privileged planes such as
// API-key management. machine credentials
// cannot mint, list, or revoke credentials — only an interactive user session
// (JWT) can. Must run after `authenticate` in the preHandler chain.
export async function requireInteractiveAuth(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const user = request.user;

  if (!user) {
    return sendForbidden(reply, 'FORBIDDEN', 'Authentication required');
  }

  if (user.authMethod === 'api_key') {
    log.warn(
      { userId: user.id, path: request.url },
      'API-key principal blocked from interactive-only route'
    );
    return sendForbidden(
      reply,
      'REQUIRES_INTERACTIVE_AUTH',
      'API key credentials cannot be used to manage API keys. Sign in with a user session.'
    );
  }
}
