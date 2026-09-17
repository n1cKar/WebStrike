/**
 * Audit-safe logging. WebStrike logs request metadata only — never bodies,
 * cookies, tokens, response contents or evidence. Kept deliberately small and
 * temporary; nothing here is persisted.
 */

export type AuditEvent =
  | "session.create"
  | "session.end"
  | "request.execute"
  | "auth.register"
  | "auth.login"
  | "auth.logout"
  | "security.refuse";

export interface AuditRecord {
  event: AuditEvent;
  actor?: string;
  target?: string;
  outcome: "allow" | "deny";
  reason?: string;
  meta?: Record<string, string | number | boolean>;
}

export function audit(record: AuditRecord): void {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    scope: "webstrike",
    ...record,
  });
  if (record.outcome === "deny") {
    console.warn(line);
  } else {
    console.info(line);
  }
}
