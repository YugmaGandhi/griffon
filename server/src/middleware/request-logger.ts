import { FastifyRequest, FastifyReply, HookHandlerDoneFunction } from 'fastify';
import { createLogger } from '../utils/logger';

const log = createLogger('HTTP');

// onRequest hook — fires when request arrives
export function onRequestLogger(
  request: FastifyRequest,
  _reply: FastifyReply,
  done: HookHandlerDoneFunction
) {
  log.info(
    {
      reqId: request.id,
      method: request.method,
      url: request.url,
      ip: request.ip,
      userAgent: request.headers['user-agent'],
    },
    'Request received'
  );
  done();
}

// onResponse hook — fires when response is sent
export function onResponseLogger(
  request: FastifyRequest,
  reply: FastifyReply,
  done: HookHandlerDoneFunction
) {
  log.info(
    {
      reqId: request.id,
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      responseTime: reply.elapsedTime,
    },
    'Request completed'
  );
  done();
}
