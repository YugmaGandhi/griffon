import { InferSelectModel, InferInsertModel } from 'drizzle-orm';
import { users, refreshTokens, roles, permissions } from '../db/schema';

// Infer types directly from Drizzle schema
// These stay in sync automatically when schema changes
export type User = InferSelectModel<typeof users>;
export type NewUser = InferInsertModel<typeof users>;
export type RefreshToken = InferSelectModel<typeof refreshTokens>;
export type Role = InferSelectModel<typeof roles>;
export type Permission = InferSelectModel<typeof permissions>;

// User shape safe to return in API responses
// Never includes passwordHash
export type SafeUser = Omit<User, 'passwordHash'>;

// What gets embedded in JWT payload
export type TokenUser = {
  id: string;
  email: string;
  roles: string[];
  permissions: string[];
};
