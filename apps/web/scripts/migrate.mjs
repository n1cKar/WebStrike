import { neon } from "@neondatabase/serverless";

/**
 * Minimal migration runner.
 *
 * Only the `users` table exists. Testing data is never persisted, so there are
 * deliberately no other migrations. Idempotent — safe to run repeatedly.
 *
 * Usage: node --env-file=.env scripts/migrate.mjs
 */
const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is not set");
  process.exit(1);
}

const sql = neon(url);

const DDL = [
  `create extension if not exists pgcrypto`,
  `create table if not exists users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    password_hash text not null,
    created_at timestamptz not null default now()
  )`,
];

try {
  for (const statement of DDL) {
    await sql.query(statement);
  }
  const rows = await sql.query(
    "select column_name from information_schema.columns where table_name = 'users' order by ordinal_position",
  );
  console.log("migration ok; users columns:", rows.map((r) => r.column_name).join(", "));
} catch (error) {
  console.error("migration failed:", error instanceof Error ? error.message : error);
  process.exit(1);
}
