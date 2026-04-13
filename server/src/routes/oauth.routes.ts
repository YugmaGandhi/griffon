import { FastifyInstance } from 'fastify';
import { oauthService } from '../services/oauth.service';
import { authService } from '../services/auth.service';
import {
  getOAuthProvider,
  getEnabledProviders,
} from '../config/oauth-providers';
import { env } from '../config/env';
import { createLogger } from '../utils/logger';

const log = createLogger('OAuthRoutes');

// Simple in-memory state store — prevents CSRF attacks
// State token is generated on /oauth/:provider
// Verified on /oauth/:provider/callback
// In production consider Redis for distributed deployments
const stateStore = new Map<string, { provider: string; expiresAt: Date }>();

// Clean up expired states every 5 minutes
setInterval(
  () => {
    const now = new Date();
    for (const [key, value] of stateStore.entries()) {
      if (value.expiresAt < now) stateStore.delete(key);
    }
  },
  5 * 60 * 1000
);

export function oauthRoutes(
  app: FastifyInstance,
  _options: unknown,
  done: () => void
) {
  const enabledProviders = getEnabledProviders();

  if (enabledProviders.length === 0) {
    log.warn('No OAuth providers configured — skipping OAuth routes');
    done();
    return;
  }

  log.info({ providers: enabledProviders }, 'OAuth providers enabled');

  // ── GET /oauth/providers ──────────────────────────────
  // Returns list of enabled providers
  // Frontend uses this to know which login buttons to show
  app.get('/oauth/providers', async (_request, reply) => {
    return reply.send({
      success: true,
      data: { providers: enabledProviders },
    });
  });

  // ── GET /oauth/:provider ──────────────────────────────
  // Redirects to provider consent screen
  app.get('/oauth/:provider', async (request, reply) => {
    const { provider } = request.params as { provider: string };

    const providerConfig = getOAuthProvider(provider);
    if (!providerConfig) {
      return reply.status(404).send({
        success: false,
        error: {
          code: 'PROVIDER_NOT_FOUND',
          message: `OAuth provider '${provider}' is not configured`,
        },
      });
    }

    // Generate and store state token — expires in 10 minutes
    const state = oauthService.generateState();
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 10);
    stateStore.set(state, { provider, expiresAt });

    const authUrl = oauthService.buildAuthUrl(provider, state);

    log.info({ provider }, 'Redirecting to OAuth provider');
    return reply.redirect(authUrl);
  });

  // ── GET /oauth/:provider/callback ─────────────────────
  // Handles callback from provider
  app.get('/oauth/:provider/callback', async (request, reply) => {
    const { provider } = request.params as { provider: string };
    const { code, state, error } = request.query as {
      code?: string;
      state?: string;
      error?: string;
    };

    // User denied permission
    if (error) {
      log.warn({ provider, error }, 'OAuth denied by user');
      return reply.redirect(`${env.OAUTH_FAILURE_REDIRECT}?error=oauth_denied`);
    }

    // Validate state — CSRF protection
    if (!state || !stateStore.has(state)) {
      log.warn({ provider }, 'Invalid OAuth state — possible CSRF attack');
      return reply.redirect(
        `${env.OAUTH_FAILURE_REDIRECT}?error=invalid_state`
      );
    }

    const storedState = stateStore.get(state)!;
    stateStore.delete(state); // Single use

    // Make sure state was for this provider
    if (storedState.provider !== provider) {
      log.warn({ provider }, 'OAuth state provider mismatch');
      return reply.redirect(
        `${env.OAUTH_FAILURE_REDIRECT}?error=invalid_state`
      );
    }

    if (!code) {
      return reply.redirect(`${env.OAUTH_FAILURE_REDIRECT}?error=missing_code`);
    }

    try {
      // Exchange code for access token
      const accessToken = await oauthService.exchangeCode(provider, code);

      // Fetch user profile
      const profile = await oauthService.fetchProfile(provider, accessToken);

      // Login or create user
      const result = await authService.oauthLogin({
        profile,
        providerName: provider,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      });

      // Redirect with Griffon tokens
      const redirectParams = new URLSearchParams({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });

      log.info({ provider, userId: result.user.id }, 'OAuth login successful');
      return reply.redirect(
        `${env.OAUTH_SUCCESS_REDIRECT}?${redirectParams.toString()}`
      );
    } catch (err) {
      log.error({ err, provider }, 'OAuth callback failed');
      return reply.redirect(`${env.OAUTH_FAILURE_REDIRECT}?error=oauth_failed`);
    }
  });

  done();
}
