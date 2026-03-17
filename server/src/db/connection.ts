import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as schema from './schema';
import { env } from '../config/env';

// Connection pool — reuses connections instead of creating
// a new one for every query. Critical for performance.
const pool = new Pool({
  connectionString: env.DATABASE_URL,
  min: 2, // always keep 2 connections open
  max: 10, // never open more than 10 at once
  ssl: env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});

// Test the connection when this module loads
pool.on('error', (err) => {
  console.error('Unexpected database pool error:', err);
});

// db is what you import everywhere to run queries
export const db = drizzle(pool, { schema });

// Export pool separately so we can close it gracefully on shutdown
export { pool };
