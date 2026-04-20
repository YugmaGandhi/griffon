import {
  pgTable,
  uuid,
  varchar,
  boolean,
  integer,
  timestamp,
  inet,
  jsonb,
  pgEnum,
  primaryKey,
  text,
  uniqueIndex,
  index,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// ── Enums ───────────────────────────────────────────────
export const emailTokenTypeEnum = pgEnum('email_token_type', [
  'email_verification',
  'password_reset',
]);

export const auditEventTypeEnum = pgEnum('audit_event_type', [
  'user_registered',
  'user_login',
  'user_logout',
  'login_failed',
  'account_locked',
  'password_changed',
  'password_reset_requested',
  'email_verified',
  'token_refreshed',
  'role_assigned',
  'role_removed',
  'oauth_login',
  'org_created',
  'org_updated',
  'org_deleted',
  'org_member_invited',
  'org_member_joined',
  'org_member_removed',
  'org_member_role_changed',
  'org_switched',
  'session_revoked',
  'all_sessions_revoked',
  'user_disabled',
  'user_enabled',
  'user_created_by_admin',
  'account_deletion_requested',
  'account_deletion_cancelled',
  'account_deleted',
  // Phase 2 — MFA
  'mfa_enrolled',
  'mfa_disabled',
  'mfa_verified',
  'mfa_recovery_used',
  'mfa_recovery_regenerated',
  'org_mfa_enforced',
  'org_mfa_unenforced',
  // Phase 2 — API Keys
  'api_key_created',
  'api_key_revoked',
  'api_key_used',
]);

export const deletionStatusEnum = pgEnum('deletion_status', [
  'pending',
  'cancelled',
  'completed',
]);

export const webhookDeliveryStatusEnum = pgEnum('webhook_delivery_status', [
  'pending',
  'success',
  'failed',
]);

export const orgInvitationStatusEnum = pgEnum('org_invitation_status', [
  'pending',
  'accepted',
  'expired',
  'revoked',
]);

// ── Organizations ──────────────────────────────────────
export const organizations = pgTable('organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  slug: varchar('slug', { length: 255 }).notNull().unique(),
  logoUrl: varchar('logo_url', { length: 2048 }),
  metadata: jsonb('metadata').notNull().default({}),
  // FK to users.id, set null on user deletion so the org isn't orphaned.
  // The AnyPgColumn cast breaks the otherwise-circular type inference
  // between users <-> organizations (users.activeOrgId references back).
  createdBy: uuid('created_by').references((): AnyPgColumn => users.id, {
    onDelete: 'set null',
  }),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── Users ───────────────────────────────────────────────
export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: varchar('password_hash', { length: 255 }),
  isVerified: boolean('is_verified').notNull().default(false),
  isDisabled: boolean('is_disabled').notNull().default(false),
  isLocked: boolean('is_locked').notNull().default(false),
  failedAttempts: integer('failed_attempts').notNull().default(0),
  lockedUntil: timestamp('locked_until', { withTimezone: true }),
  lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
  oauthProvider: varchar('oauth_provider', { length: 50 }),
  oauthId: varchar('oauth_id', { length: 255 }),
  activeOrgId: uuid('active_org_id').references(() => organizations.id, {
    onDelete: 'set null',
  }),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── Refresh Tokens ──────────────────────────────────────
export const refreshTokens = pgTable('refresh_tokens', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: varchar('token_hash', { length: 255 }).notNull().unique(),
  deviceInfo: varchar('device_info', { length: 500 }),
  ipAddress: inet('ip_address'),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── Email Tokens ────────────────────────────────────────
export const emailTokens = pgTable('email_tokens', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: varchar('token_hash', { length: 255 }).notNull().unique(),
  type: emailTokenTypeEnum('type').notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  usedAt: timestamp('used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── Roles ───────────────────────────────────────────────
export const roles = pgTable('roles', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  description: text('description'),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── Permissions ─────────────────────────────────────────
export const permissions = pgTable('permissions', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  resource: varchar('resource', { length: 50 }).notNull(),
  action: varchar('action', { length: 50 }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── User Roles (junction) ───────────────────────────────
export const userRoles = pgTable(
  'user_roles',
  {
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    roleId: uuid('role_id')
      .notNull()
      .references(() => roles.id, { onDelete: 'cascade' }),
    assignedBy: uuid('assigned_by').references(() => users.id, {
      onDelete: 'set null',
    }),
    assignedAt: timestamp('assigned_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [primaryKey({ columns: [table.userId, table.roleId] })]
);

// ── Role Permissions (junction) ─────────────────────────
export const rolePermissions = pgTable(
  'role_permissions',
  {
    roleId: uuid('role_id')
      .notNull()
      .references(() => roles.id, { onDelete: 'cascade' }),
    permissionId: uuid('permission_id')
      .notNull()
      .references(() => permissions.id, { onDelete: 'cascade' }),
  },
  (table) => [primaryKey({ columns: [table.roleId, table.permissionId] })]
);

// ── Audit Logs ──────────────────────────────────────────
export const auditLogs = pgTable('audit_logs', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
  eventType: auditEventTypeEnum('event_type').notNull(),
  ipAddress: inet('ip_address'),
  userAgent: varchar('user_agent', { length: 500 }),
  metadata: jsonb('metadata').default({}),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── Org Members ────────────────────────────────────────
export const orgMembers = pgTable(
  'org_members',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    role: varchar('role', { length: 50 }).notNull().default('member'),
    joinedAt: timestamp('joined_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('org_members_org_user_idx').on(table.orgId, table.userId),
  ]
);

// ── Org Invitations ────────────────────────────────────
export const orgInvitations = pgTable('org_invitations', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id')
    .notNull()
    .references(() => organizations.id, { onDelete: 'cascade' }),
  email: varchar('email', { length: 255 }).notNull(),
  role: varchar('role', { length: 50 }).notNull().default('member'),
  invitedBy: uuid('invited_by').references(() => users.id, {
    onDelete: 'set null',
  }),
  tokenHash: varchar('token_hash', { length: 255 }).notNull().unique(),
  status: orgInvitationStatusEnum('status').notNull().default('pending'),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  acceptedAt: timestamp('accepted_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── Org Roles (custom roles per organization) ─────────
export const orgRoles = pgTable(
  'org_roles',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 100 }).notNull(),
    description: text('description'),
    isSystem: boolean('is_system').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [uniqueIndex('org_roles_org_name_idx').on(table.orgId, table.name)]
);

// ── Org Permissions (permissions scoped per organization)
export const orgPermissions = pgTable(
  'org_permissions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 100 }).notNull(),
    resource: varchar('resource', { length: 50 }).notNull(),
    action: varchar('action', { length: 50 }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('org_permissions_org_name_idx').on(table.orgId, table.name),
  ]
);

// ── Org Member Roles (junction: member ↔ custom org role)
export const orgMemberRoles = pgTable(
  'org_member_roles',
  {
    orgMemberId: uuid('org_member_id')
      .notNull()
      .references(() => orgMembers.id, { onDelete: 'cascade' }),
    orgRoleId: uuid('org_role_id')
      .notNull()
      .references(() => orgRoles.id, { onDelete: 'cascade' }),
    assignedBy: uuid('assigned_by').references(() => users.id, {
      onDelete: 'set null',
    }),
    assignedAt: timestamp('assigned_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [primaryKey({ columns: [table.orgMemberId, table.orgRoleId] })]
);

// ── Org Role Permissions (junction: org role ↔ org permission)
export const orgRolePermissions = pgTable(
  'org_role_permissions',
  {
    orgRoleId: uuid('org_role_id')
      .notNull()
      .references(() => orgRoles.id, { onDelete: 'cascade' }),
    orgPermissionId: uuid('org_permission_id')
      .notNull()
      .references(() => orgPermissions.id, { onDelete: 'cascade' }),
  },
  (table) => [primaryKey({ columns: [table.orgRoleId, table.orgPermissionId] })]
);

// ── Deletion Requests ───────────────────────────────────
export const deletionRequests = pgTable('deletion_requests', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
  requestedAt: timestamp('requested_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
  scheduledPurgeAt: timestamp('scheduled_purge_at', {
    withTimezone: true,
  }).notNull(),
  status: deletionStatusEnum('status').notNull().default('pending'),
  cancelledAt: timestamp('cancelled_at', { withTimezone: true }),
  forcedByAdmin: boolean('forced_by_admin').notNull().default(false),
});

// ── Webhook Endpoints ───────────────────────────────────
// One endpoint = one URL an org wants us to POST events to.
// events: jsonb array of event type strings e.g. ["user.login", "user.registered"]
// secretHash: SHA-256 of the signing secret. Raw secret shown once, never stored.
export const webhookEndpoints = pgTable('webhook_endpoints', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id')
    .notNull()
    .references(() => organizations.id, { onDelete: 'cascade' }),
  url: varchar('url', { length: 2048 }).notNull(),
  events: jsonb('events').notNull().default([]),
  secretHash: varchar('secret_hash', { length: 255 }).notNull(),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── Webhook Deliveries ──────────────────────────────────
// Append-only delivery log. One row per delivery attempt batch.
// status 'pending' = waiting first attempt OR scheduled for retry.
// nextRetryAt drives the retry job query.
export const webhookDeliveries = pgTable('webhook_deliveries', {
  id: uuid('id').primaryKey().defaultRandom(),
  webhookEndpointId: uuid('webhook_endpoint_id')
    .notNull()
    .references(() => webhookEndpoints.id, { onDelete: 'cascade' }),
  eventType: varchar('event_type', { length: 100 }).notNull(),
  payload: jsonb('payload').notNull(),
  status: webhookDeliveryStatusEnum('status').notNull().default('pending'),
  attempts: integer('attempts').notNull().default(0),
  nextRetryAt: timestamp('next_retry_at', { withTimezone: true }),
  lastAttemptAt: timestamp('last_attempt_at', { withTimezone: true }),
  responseCode: integer('response_code'),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── MFA Settings ───────────────────────────────────────
// One row per user. Created at enrollment start.
// isEnabled = false until the user proves the first TOTP code works.
// encryptedSecret: AES-256-GCM encrypted TOTP seed ("iv:authTag:ciphertext").
// We encrypt (not hash) because we need the raw secret at verify time.
export const mfaSettings = pgTable('mfa_settings', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .unique()
    .references(() => users.id, { onDelete: 'cascade' }),
  encryptedSecret: varchar('encrypted_secret', { length: 255 }).notNull(),
  isEnabled: boolean('is_enabled').notNull().default(false),
  enabledAt: timestamp('enabled_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── MFA Recovery Codes ──────────────────────────────────
// 8 rows per user, created at enrollment.
// codeHash: SHA-256 of the raw recovery code (high-entropy, no Argon2id needed).
// Row is deleted on use — single-use is enforced by deletion, not a flag.
export const mfaRecoveryCodes = pgTable(
  'mfa_recovery_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    codeHash: varchar('code_hash', { length: 255 }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [index('mfa_recovery_codes_user_id_idx').on(t.userId)]
);

// ── Org MFA Policies ────────────────────────────────────
// One row per org (optional — only created when an org enables MFA enforcement).
// requireMfa = true blocks org-scoped endpoints for members without MFA enrolled.
// enforcedAt records when the policy was turned on, for audit purposes.
export const orgMfaPolicies = pgTable('org_mfa_policies', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id')
    .notNull()
    .unique()
    .references(() => organizations.id, { onDelete: 'cascade' }),
  requireMfa: boolean('require_mfa').notNull().default(false),
  enforcedAt: timestamp('enforced_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// ── API Keys ────────────────────────────────────────────
// One row per key. keyHash is SHA-256 of the full key — plaintext returned once
// at creation, never stored. prefix stores the first 10 chars for log identification.
// permissions: frozen string[] of granted scopes (not live user permissions).
// revokedAt: soft-revoke — row stays for audit history.
export const apiKeys = pgTable(
  'api_keys',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    orgId: uuid('org_id').references(() => organizations.id, {
      onDelete: 'cascade',
    }),
    name: varchar('name', { length: 255 }).notNull(),
    prefix: varchar('prefix', { length: 20 }).notNull(),
    keyHash: varchar('key_hash', { length: 255 }).notNull().unique(),
    permissions: jsonb('permissions').notNull().default([]),
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    index('api_keys_user_id_idx').on(t.userId),
    index('api_keys_org_id_idx').on(t.orgId),
  ]
);

// ── Relations (for Drizzle joins) ───────────────────────
export const organizationsRelations = relations(
  organizations,
  ({ one, many }) => ({
    createdByUser: one(users, {
      fields: [organizations.createdBy],
      references: [users.id],
    }),
    members: many(orgMembers),
    invitations: many(orgInvitations),
    orgRoles: many(orgRoles),
    orgPermissions: many(orgPermissions),
    webhookEndpoints: many(webhookEndpoints),
  })
);

export const usersRelations = relations(users, ({ one, many }) => ({
  refreshTokens: many(refreshTokens),
  emailTokens: many(emailTokens),
  userRoles: many(userRoles),
  auditLogs: many(auditLogs),
  orgMemberships: many(orgMembers),
  deletionRequests: many(deletionRequests),
  activeOrg: one(organizations, {
    fields: [users.activeOrgId],
    references: [organizations.id],
  }),
}));

export const rolesRelations = relations(roles, ({ many }) => ({
  userRoles: many(userRoles),
  rolePermissions: many(rolePermissions),
}));

export const permissionsRelations = relations(permissions, ({ many }) => ({
  rolePermissions: many(rolePermissions),
}));

export const orgMembersRelations = relations(orgMembers, ({ one, many }) => ({
  organization: one(organizations, {
    fields: [orgMembers.orgId],
    references: [organizations.id],
  }),
  user: one(users, {
    fields: [orgMembers.userId],
    references: [users.id],
  }),
  memberRoles: many(orgMemberRoles),
}));

export const orgInvitationsRelations = relations(orgInvitations, ({ one }) => ({
  organization: one(organizations, {
    fields: [orgInvitations.orgId],
    references: [organizations.id],
  }),
  invitedByUser: one(users, {
    fields: [orgInvitations.invitedBy],
    references: [users.id],
  }),
}));

export const orgRolesRelations = relations(orgRoles, ({ one, many }) => ({
  organization: one(organizations, {
    fields: [orgRoles.orgId],
    references: [organizations.id],
  }),
  memberRoles: many(orgMemberRoles),
  rolePermissions: many(orgRolePermissions),
}));

export const orgPermissionsRelations = relations(
  orgPermissions,
  ({ one, many }) => ({
    organization: one(organizations, {
      fields: [orgPermissions.orgId],
      references: [organizations.id],
    }),
    rolePermissions: many(orgRolePermissions),
  })
);

export const orgMemberRolesRelations = relations(orgMemberRoles, ({ one }) => ({
  member: one(orgMembers, {
    fields: [orgMemberRoles.orgMemberId],
    references: [orgMembers.id],
  }),
  role: one(orgRoles, {
    fields: [orgMemberRoles.orgRoleId],
    references: [orgRoles.id],
  }),
}));

export const deletionRequestsRelations = relations(
  deletionRequests,
  ({ one }) => ({
    user: one(users, {
      fields: [deletionRequests.userId],
      references: [users.id],
    }),
  })
);

export const orgRolePermissionsRelations = relations(
  orgRolePermissions,
  ({ one }) => ({
    role: one(orgRoles, {
      fields: [orgRolePermissions.orgRoleId],
      references: [orgRoles.id],
    }),
    permission: one(orgPermissions, {
      fields: [orgRolePermissions.orgPermissionId],
      references: [orgPermissions.id],
    }),
  })
);

export const webhookEndpointsRelations = relations(
  webhookEndpoints,
  ({ one, many }) => ({
    organization: one(organizations, {
      fields: [webhookEndpoints.orgId],
      references: [organizations.id],
    }),
    deliveries: many(webhookDeliveries),
  })
);

export const webhookDeliveriesRelations = relations(
  webhookDeliveries,
  ({ one }) => ({
    endpoint: one(webhookEndpoints, {
      fields: [webhookDeliveries.webhookEndpointId],
      references: [webhookEndpoints.id],
    }),
  })
);

export const mfaSettingsRelations = relations(mfaSettings, ({ one }) => ({
  user: one(users, {
    fields: [mfaSettings.userId],
    references: [users.id],
  }),
}));

export const mfaRecoveryCodesRelations = relations(
  mfaRecoveryCodes,
  ({ one }) => ({
    user: one(users, {
      fields: [mfaRecoveryCodes.userId],
      references: [users.id],
    }),
  })
);

export const orgMfaPoliciesRelations = relations(orgMfaPolicies, ({ one }) => ({
  organization: one(organizations, {
    fields: [orgMfaPolicies.orgId],
    references: [organizations.id],
  }),
}));

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
  user: one(users, {
    fields: [apiKeys.userId],
    references: [users.id],
  }),
  organization: one(organizations, {
    fields: [apiKeys.orgId],
    references: [organizations.id],
  }),
}));
