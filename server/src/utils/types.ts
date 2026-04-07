import { InferSelectModel, InferInsertModel } from 'drizzle-orm';
import {
  users,
  refreshTokens,
  roles,
  permissions,
  organizations,
  orgMembers,
  orgInvitations,
  orgRoles,
  orgPermissions,
} from '../db/schema';

// Infer types directly from Drizzle schema
// These stay in sync automatically when schema changes
export type User = InferSelectModel<typeof users>;
export type NewUser = InferInsertModel<typeof users>;
export type RefreshToken = InferSelectModel<typeof refreshTokens>;
export type Role = InferSelectModel<typeof roles>;
export type Permission = InferSelectModel<typeof permissions>;
export type Organization = InferSelectModel<typeof organizations>;
export type NewOrganization = InferInsertModel<typeof organizations>;
export type OrgMember = InferSelectModel<typeof orgMembers>;
export type OrgInvitation = InferSelectModel<typeof orgInvitations>;
export type OrgRole = InferSelectModel<typeof orgRoles>;
export type OrgPermission = InferSelectModel<typeof orgPermissions>;

// User shape safe to return in API responses
// Never includes passwordHash
export type SafeUser = Omit<User, 'passwordHash'>;

// What gets embedded in JWT payload
// Platform claims (roles, permissions) and org claims are separate
export type TokenUser = {
  id: string;
  email: string;
  roles: string[];
  permissions: string[];
  orgId: string | null;
  orgRole: string | null;
  orgPermissions: string[];
};

// ── Utility Functions ────────────────────────────────────
// Single source of truth for stripping sensitive fields
// Use this everywhere instead of duplicating the destructure
export function toSafeUser(user: User): SafeUser {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { passwordHash, ...safeUser } = user;
  return safeUser;
}
