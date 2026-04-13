import { env } from './env';

// Shape of a normalized user profile
// Every provider returns different fields —
// we normalize them all to this shape
export type OAuthProfile = {
  id: string;
  email: string;
};

// Shape of a provider config
export type OAuthProviderConfig = {
  name: string;
  authUrl: string;
  tokenUrl: string;
  profileUrl: string;
  scopes: string[];
  clientId: string;
  clientSecret: string;
  // Normalizes provider-specific profile shape to OAuthProfile
  // Each provider returns different JSON — this handles that
  getProfile: (data: Record<string, unknown>) => OAuthProfile;
  // Some providers need special headers on profile request
  profileHeaders?: Record<string, string>;
};

// Registry — add new providers here, zero route changes needed
const registry: Record<string, OAuthProviderConfig | null> = {
  google:
    env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET
      ? {
          name: 'google',
          authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
          tokenUrl: 'https://oauth2.googleapis.com/token',
          profileUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
          scopes: ['email', 'profile'],
          clientId: env.GOOGLE_CLIENT_ID,
          clientSecret: env.GOOGLE_CLIENT_SECRET,
          getProfile: (data) => ({
            id: String(data.id),
            email: String(data.email),
          }),
        }
      : null,

  github:
    env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET
      ? {
          name: 'github',
          authUrl: 'https://github.com/login/oauth/authorize',
          tokenUrl: 'https://github.com/login/oauth/access_token',
          profileUrl: 'https://api.github.com/user',
          scopes: ['read:user', 'user:email'],
          clientId: env.GITHUB_CLIENT_ID,
          clientSecret: env.GITHUB_CLIENT_SECRET,
          profileHeaders: {
            // GitHub requires this header
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Griffon',
          },
          getProfile: (data) => ({
            id: String(data.id),
            // GitHub may not return email if set to private
            // Falls back to empty string — handled in route
            email: String(data.email ?? ''),
          }),
        }
      : null,

  microsoft:
    env.MICROSOFT_CLIENT_ID && env.MICROSOFT_CLIENT_SECRET
      ? {
          name: 'microsoft',
          authUrl:
            'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
          tokenUrl:
            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
          profileUrl: 'https://graph.microsoft.com/v1.0/me',
          scopes: ['openid', 'email', 'profile', 'User.Read'],
          clientId: env.MICROSOFT_CLIENT_ID,
          clientSecret: env.MICROSOFT_CLIENT_SECRET,
          getProfile: (data) => ({
            id: String(data.id),
            // Microsoft uses 'mail' or 'userPrincipalName'
            email: String(data.mail ?? data.userPrincipalName ?? ''),
          }),
        }
      : null,
};

// Returns config for a provider if it's enabled
// Returns null if provider is unknown or credentials not configured
export function getOAuthProvider(name: string): OAuthProviderConfig | null {
  return registry[name] ?? null;
}

// Returns list of all enabled provider names
export function getEnabledProviders(): string[] {
  return Object.entries(registry)
    .filter(([, config]) => config !== null)
    .map(([name]) => name);
}
