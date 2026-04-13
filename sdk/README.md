# @griffon/js

Official JavaScript/TypeScript SDK for [Griffon](https://github.com/YugmaGandhi/griffon).

## Installation
```bash
npm install @griffon/js
```

## Quick Start
```typescript
import { GriffonClient } from '@griffon/js'

const client = new GriffonClient({
  baseUrl: 'https://your-griffon-instance.com'
})

// Register
await client.register('user@example.com', 'password123')

// Login
const { user } = await client.login('user@example.com', 'password123')
console.log(user.email, user.roles)

// Make authenticated requests — token handled automatically
const me = await client.getMe()

// Token refresh happens automatically when expired

// Logout
await client.logout()
```

## OAuth
```typescript
// Redirect user to OAuth provider
window.location.href = client.getOAuthUrl('google')

// After redirect back — extract tokens from URL
const params = new URLSearchParams(window.location.search)
client.handleOAuthCallback(
  params.get('accessToken')!,
  params.get('refreshToken')!
)
```

## Error Handling
```typescript
import { GriffonClient, GriffonError } from '@griffon/js'

try {
  await client.login('user@example.com', 'wrongpassword')
} catch (err) {
  if (err instanceof GriffonError) {
    console.log(err.code)    // 'INVALID_CREDENTIALS'
    console.log(err.message) // 'Invalid email or password'
    console.log(err.statusCode) // 401

    // Convenience checks
    if (err.isTokenExpired) { ... }
    if (err.isRateLimited) { ... }
    if (err.isValidationError) {
      err.details?.forEach(d => console.log(d.field, d.message))
    }
  }
}
```

## Configuration
```typescript
const client = new GriffonClient({
  baseUrl: 'https://your-griffon-instance.com',
  timeout: 10000,        // Request timeout in ms (default: 10000)
  fetchImpl: customFetch // Custom fetch implementation (optional)
})
```