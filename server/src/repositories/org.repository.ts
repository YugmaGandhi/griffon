import { eq, and, count } from 'drizzle-orm';
import { db } from '../db/connection';
import {
  organizations,
  orgMembers,
  orgMemberRoles,
  orgRoles,
  orgRolePermissions,
  orgPermissions,
  users,
} from '../db/schema';
import { NewOrganization, Organization } from '../utils/types';
import { createLogger } from '../utils/logger';

const log = createLogger('OrgRepository');

export class OrgRepository {
  // ── Create ────────────────────────────────────────────
  async create(data: NewOrganization): Promise<Organization> {
    log.debug({ slug: data.slug }, 'Creating organization');

    const [org] = await db.insert(organizations).values(data).returning();
    return org;
  }

  // ── Find by ID ────────────────────────────────────────
  async findById(id: string): Promise<Organization | null> {
    const [org] = await db
      .select()
      .from(organizations)
      .where(eq(organizations.id, id));

    return org ?? null;
  }

  // ── Find by slug ──────────────────────────────────────
  async findBySlug(slug: string): Promise<Organization | null> {
    const [org] = await db
      .select()
      .from(organizations)
      .where(eq(organizations.slug, slug));

    return org ?? null;
  }

  // ── List orgs for a user ──────────────────────────────
  async findByUserId(
    userId: string
  ): Promise<(Organization & { role: string; joinedAt: Date })[]> {
    const rows = await db
      .select({
        id: organizations.id,
        name: organizations.name,
        slug: organizations.slug,
        logoUrl: organizations.logoUrl,
        metadata: organizations.metadata,
        createdBy: organizations.createdBy,
        createdAt: organizations.createdAt,
        updatedAt: organizations.updatedAt,
        role: orgMembers.role,
        joinedAt: orgMembers.joinedAt,
      })
      .from(orgMembers)
      .innerJoin(organizations, eq(orgMembers.orgId, organizations.id))
      .where(eq(orgMembers.userId, userId));

    return rows;
  }

  // ── Count orgs created by a user ──────────────────────
  async countByCreator(userId: string): Promise<number> {
    const [result] = await db
      .select({ count: count() })
      .from(organizations)
      .where(eq(organizations.createdBy, userId));

    return result.count;
  }

  // ── Update ────────────────────────────────────────────
  async update(
    id: string,
    data: Partial<Pick<Organization, 'name' | 'slug' | 'logoUrl' | 'metadata'>>
  ): Promise<Organization> {
    const [org] = await db
      .update(organizations)
      .set({ ...data, updatedAt: new Date() })
      .where(eq(organizations.id, id))
      .returning();

    return org;
  }

  // ── Delete ────────────────────────────────────────────
  async delete(id: string): Promise<void> {
    await db.delete(organizations).where(eq(organizations.id, id));
  }

  // ── Add member ────────────────────────────────────────
  async addMember(
    orgId: string,
    userId: string,
    role: string = 'member'
  ): Promise<void> {
    await db.insert(orgMembers).values({ orgId, userId, role });
  }

  // ── Find membership ───────────────────────────────────
  async findMembership(
    orgId: string,
    userId: string
  ): Promise<{ id: string; role: string } | null> {
    const [row] = await db
      .select({ id: orgMembers.id, role: orgMembers.role })
      .from(orgMembers)
      .where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)));

    return row ?? null;
  }
  // ── List members ───────────────────────────────────────
  async listMembers(orgId: string): Promise<
    {
      id: string;
      userId: string;
      email: string;
      role: string;
      joinedAt: Date;
    }[]
  > {
    const rows = await db
      .select({
        id: orgMembers.id,
        userId: orgMembers.userId,
        email: users.email,
        role: orgMembers.role,
        joinedAt: orgMembers.joinedAt,
      })
      .from(orgMembers)
      .innerJoin(users, eq(orgMembers.userId, users.id))
      .where(eq(orgMembers.orgId, orgId));

    return rows;
  }

  // ── Update member role ────────────────────────────────
  async updateMemberRole(
    orgId: string,
    userId: string,
    role: string
  ): Promise<void> {
    await db
      .update(orgMembers)
      .set({ role })
      .where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)));
  }

  // ── Remove member ─────────────────────────────────────
  async removeMember(orgId: string, userId: string): Promise<void> {
    await db
      .delete(orgMembers)
      .where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)));
  }

  // ── Count owners in org ───────────────────────────────
  async countOwners(orgId: string): Promise<number> {
    const [result] = await db
      .select({ count: count() })
      .from(orgMembers)
      .where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.role, 'owner')));

    return result.count;
  }

  // ── Get member's org context for JWT ─────────────────
  // Returns the member's built-in role + all permission names from
  // their custom org roles (orgMemberRoles → orgRoles → orgRolePermissions → orgPermissions)
  async getMemberOrgContext(
    orgId: string,
    userId: string
  ): Promise<{ role: string; permissions: string[] } | null> {
    const rows = await db
      .select({
        role: orgMembers.role,
        permissionName: orgPermissions.name,
      })
      .from(orgMembers)
      .leftJoin(orgMemberRoles, eq(orgMemberRoles.orgMemberId, orgMembers.id))
      .leftJoin(orgRoles, eq(orgRoles.id, orgMemberRoles.orgRoleId))
      .leftJoin(
        orgRolePermissions,
        eq(orgRolePermissions.orgRoleId, orgRoles.id)
      )
      .leftJoin(
        orgPermissions,
        eq(orgPermissions.id, orgRolePermissions.orgPermissionId)
      )
      .where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)));

    if (rows.length === 0) return null;

    return {
      role: rows[0].role,
      permissions: rows
        .map((r) => r.permissionName)
        .filter((name): name is string => name !== null),
    };
  }
}

export const orgRepository = new OrgRepository();
