import crypto from 'crypto';
import { getOAuthProvider, OAuthProfile } from '../config/oauth-providers';
import { env } from '../config/env';
import { createLogger } from '../utils/logger';

const log = createLogger('OAuthService');

type TokenResponse = {
  access_token: string;
  token_type: string;
  error?: string;
};

export class OAuthService {
  // This is the URL we redirect the user to
  buildAuthUrl(providerName: string, state: string): string {
    const provider = getOAuthProvider(providerName);
    if (!provider) {
      throw new Error(`OAuth provider '${providerName}' is not configured`);
    }

    const callbackUrl = `${env.OAUTH_CALLBACK_BASE_URL}/auth/oauth/${providerName}/callback`;

    const params = new URLSearchParams({
      client_id: provider.clientId,
      redirect_uri: callbackUrl,
      response_type: 'code',
      scope: provider.scopes.join(' '),
      state,
      // Needed for Google to return refresh token
      access_type: 'offline',
    });

    return `${provider.authUrl}?${params.toString()}`;
  }

  // Exchange code for access token
  async exchangeCode(providerName: string, code: string): Promise<string> {
    const provider = getOAuthProvider(providerName);
    if (!provider) {
      throw new Error(`OAuth provider '${providerName}' is not configured`);
    }

    const callbackUrl = `${env.OAUTH_CALLBACK_BASE_URL}/auth/oauth/${providerName}/callback`;

    log.debug({ provider: providerName }, 'Exchanging OAuth code for token');

    const response = await fetch(provider.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        // GitHub requires JSON response
        Accept: 'application/json',
      },
      body: new URLSearchParams({
        code,
        client_id: provider.clientId,
        client_secret: provider.clientSecret,
        redirect_uri: callbackUrl,
        grant_type: 'authorization_code',
      }),
    });

    const data = (await response.json()) as TokenResponse;

    if (data.error || !data.access_token) {
      log.error(
        { provider: providerName, error: data.error },
        'Failed to exchange OAuth code'
      );
      throw new Error(
        `OAuth token exchange failed: ${data.error ?? 'unknown'}`
      );
    }

    return data.access_token;
  }

  // Fetch user profile
  async fetchProfile(
    providerName: string,
    accessToken: string
  ): Promise<OAuthProfile> {
    const provider = getOAuthProvider(providerName);
    if (!provider) {
      throw new Error(`OAuth provider '${providerName}' is not configured`);
    }

    log.debug({ provider: providerName }, 'Fetching OAuth user profile');

    const response = await fetch(provider.profileUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...provider.profileHeaders,
      },
    });

    const data = (await response.json()) as Record<string, unknown>;
    const profile = provider.getProfile(data);

    // GitHub-specific: email can be private
    // Need to fetch from separate endpoint
    if (providerName === 'github' && !profile.email) {
      const emailProfile = await this.fetchGitHubEmail(accessToken);
      profile.email = emailProfile;
    }

    if (!profile.email) {
      throw new Error('Could not retrieve email from OAuth provider');
    }

    return profile;
  }

  // GitHub email fallback
  // GitHub users can hide email — fetch from /user/emails
  private async fetchGitHubEmail(accessToken: string): Promise<string> {
    const response = await fetch('https://api.github.com/user/emails', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Griffon',
      },
    });

    const emails = (await response.json()) as Array<{
      email: string;
      primary: boolean;
      verified: boolean;
    }>;

    // Find primary verified email
    const primary = emails.find((e) => e.primary && e.verified);
    return primary?.email ?? '';
  }

  // Generate state token
  // CSRF protection — verified on callback
  generateState(): string {
    return crypto.randomBytes(16).toString('hex');
  }
}

export const oauthService = new OAuthService();
