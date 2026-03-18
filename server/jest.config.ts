import type { Config } from 'jest'

const config: Config = {
  // Use ts-jest so Jest understands TypeScript directly
  preset: 'ts-jest',
  testEnvironment: 'node',

  // Where to find tests
  roots: ['<rootDir>/src'],
  testMatch: [
    '**/__tests__/**/*.test.ts',
  ],

  // Module name mapping — so imports resolve correctly
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },

  // Setup file that runs before every test file
  setupFilesAfterEnv: ['<rootDir>/src/__tests__/setup.ts'],

  // Coverage settings
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.test.ts',
    '!src/db/migrations/**',
    '!src/server.ts',   // entry point — hard to unit test
  ],
  coverageThreshold: {
    global: {
      branches: 20,
      functions: 20,
      lines: 20,
      statements: 20,
    },
  },

  // Show individual test results
  verbose: true,

  // Fail fast in CI — stop after first failure
  bail: process.env.CI === 'true' ? 1 : 0,
}

export default config