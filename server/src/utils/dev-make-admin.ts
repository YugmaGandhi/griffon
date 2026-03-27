// DEV ONLY — promotes a user to admin role
// Usage: npm run dev:make-admin test@example.com
import { db } from '../db/connection';
import { users, roles, userRoles } from '../db/schema';
import { eq } from 'drizzle-orm';
import dotenv from 'dotenv';

dotenv.config();

const email = process.argv[2];

if (!email) {
  console.error('Usage: npm run dev:make-admin <email>');
  process.exit(1);
}

async function makeAdmin() {
  const [user] = await db.select().from(users).where(eq(users.email, email));

  if (!user) {
    console.error(`User not found: ${email}`);
    process.exit(1);
  }

  const [adminRole] = await db
    .select()
    .from(roles)
    .where(eq(roles.name, 'admin'));

  if (!adminRole) {
    console.error('Admin role not found — run migrations first');
    process.exit(1);
  }

  await db
    .insert(userRoles)
    .values({ userId: user.id, roleId: adminRole.id })
    .onConflictDoNothing();

  console.log(`✅ ${email} is now an admin`);
  process.exit(0);
}

void makeAdmin();
