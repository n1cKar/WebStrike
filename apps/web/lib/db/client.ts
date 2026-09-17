import { neon } from "@neondatabase/serverless";
import { drizzle, type NeonHttpDatabase } from "drizzle-orm/neon-http";
import * as schema from "./schema";

/**
 * DATABASE DECISION
 * -----------------
 * Testing data is never persisted. A database is used only when an operator
 * configures one for account storage; otherwise WebStrike runs with an
 * in-memory account store. When present, PostgreSQL is Neon via Drizzle.
 */
export type Database = NeonHttpDatabase<typeof schema>;

declare global {
  var __webstrikeDb: Database | null | undefined;
}

export function getDatabase(): Database | null {
  if (globalThis.__webstrikeDb !== undefined) return globalThis.__webstrikeDb;

  const url = process.env.DATABASE_URL;
  if (!url) {
    globalThis.__webstrikeDb = null;
    return null;
  }

  const sql = neon(url);
  globalThis.__webstrikeDb = drizzle(sql, { schema });
  return globalThis.__webstrikeDb;
}

export function isDatabaseConfigured(): boolean {
  return Boolean(process.env.DATABASE_URL);
}