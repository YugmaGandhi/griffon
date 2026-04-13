export type GriffonConfig = {
  baseUrl: string
  // Optional timeout in milliseconds — default 10000
  timeout?: number
  // Optional custom fetch implementation
  // Useful for React Native or test environments
  fetchImpl?: typeof fetch
}

export type AuthUser = {
  id: string
  email: string
  isVerified: boolean
  roles: string[]
  permissions: string[]
  createdAt: string
  updatedAt: string
}

export type TokenPair = {
  accessToken: string
  refreshToken: string
  expiresIn: number
}

export type LoginResult = TokenPair & {
  user: AuthUser
}

export type RegisterResult = {
  user: {
    id: string
    email: string
    isVerified: boolean
    createdAt: string
  }
  message: string
}

export type ApiResponse<T> = {
  success: boolean
  data: T
}

export type ApiErrorResponse = {
  success: false
  error: {
    code: string
    message: string
    details?: { field: string; message: string }[]
  }
}