// Single source of truth for all Griffon API endpoints
// If server routes change — update here only
// SDK methods reference these constants, never hardcode paths

export const API_PATHS = {
  auth: {
    register: '/auth/register',
    login: '/auth/login',
    logout: '/auth/logout',
    refresh: '/auth/refresh',
    me: '/auth/me',
    verifyEmail: '/auth/verify-email',
    forgotPassword: '/auth/forgot-password',
    resetPassword: '/auth/reset-password',
  },
  oauth: {
    provider: (provider: string) => `/auth/oauth/${provider}`,
    providers: '/auth/oauth/providers',
  },
} as const