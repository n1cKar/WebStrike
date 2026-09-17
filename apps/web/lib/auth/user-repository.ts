import type { UserRow } from "../db/schema";
import { getDatabase } from "../db/client";
import { users } from "../db/schema";
import { eq } from "drizzle-orm";

export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  createdAt: Date;
}

export interface UserRepository {
  readonly driver: "postgres" | "memory";
  findByEmail(email: string): Promise<UserRecord | null>;
  findById(id: string): Promise<UserRecord | null>;
  create(email: string, passwordHash: string): Promise<UserRecord>;
}

function fromRow(row: UserRow): UserRecord {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.passwordHash,
    createdAt: row.createdAt,
  };
}

class DrizzleUserRepository implements UserRepository {
  readonly driver = "postgres" as const;

  async findByEmail(email: string): Promise<UserRecord | null> {
    const db = getDatabase();
    if (!db) return null;
    const [row] = await db.select().from(users).where(eq(users.email, email)).limit(1);
    return row ? fromRow(row) : null;
  }

  async findById(id: string): Promise<UserRecord | null> {
    const db = getDatabase();
    if (!db) return null;
    const [row] = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return row ? fromRow(row) : null;
  }

  async create(email: string, passwordHash: string): Promise<UserRecord> {
    const db = getDatabase();
    if (!db) throw new Error("database is not configured");
    const [row] = await db.insert(users).values({ email, passwordHash }).returning();
    if (!row) throw new Error("failed to create user");
    return fromRow(row);
  }
}

declare global {
  var __webstrikeMemoryUsers: Map<string, UserRecord> | undefined;
}

function memoryUsers(): Map<string, UserRecord> {
  if (!globalThis.__webstrikeMemoryUsers) {
    globalThis.__webstrikeMemoryUsers = new Map();
  }
  return globalThis.__webstrikeMemoryUsers;
}

/**
 * Development-only account store. Keeps accounts in process memory so the app
 * is usable without provisioning PostgreSQL. Never used when DATABASE_URL is set.
 */
class InMemoryUserRepository implements UserRepository {
  readonly driver = "memory" as const;

  async findByEmail(email: string): Promise<UserRecord | null> {
    return memoryUsers().get(email.toLowerCase()) ?? null;
  }

  async findById(id: string): Promise<UserRecord | null> {
    for (const user of memoryUsers().values()) {
      if (user.id === id) return user;
    }
    return null;
  }

  async create(email: string, passwordHash: string): Promise<UserRecord> {
    const normalized = email.toLowerCase();
    if (memoryUsers().has(normalized)) {
      const err = new Error("email already registered");
      (err as NodeJS.ErrnoException).code = "DUPLICATE";
      throw err;
    }
    const record: UserRecord = {
      id: globalThis.crypto.randomUUID(),
      email: normalized,
      passwordHash,
      createdAt: new Date(),
    };
    memoryUsers().set(normalized, record);
    return record;
  }
}

export function getUserRepository(): UserRepository {
  return getDatabase() ? new DrizzleUserRepository() : new InMemoryUserRepository();
}