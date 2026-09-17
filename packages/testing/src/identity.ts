import type { Identity } from "./types";

/**
 * Identity helpers for authorization comparison.
 *
 * Markers are user-identifying strings that may legitimately appear in a
 * response the user owns (username, email, role label). They are never derived
 * from credential material such as cookies or bearer tokens.
 */
export function identityMarkers(identity: Identity | undefined): string[] {
  if (!identity) return [];
  const markers = new Set<string>();
  const label = identity.label.trim();
  if (label.length >= 3) {
    markers.add(label);
    if (label.includes("@")) {
      const local = label.split("@")[0]!.trim();
      if (local.length >= 3) markers.add(local);
    }
  }
  if (identity.id.length >= 4 && !/^identity|^user[\-_]?[ab]$/i.test(identity.id)) {
    markers.add(identity.id);
  }
  return [...markers].filter((m) => m.length >= 3);
}

/** True when the identity is explicitly marked as privileged/administrative. */
export function isPrivileged(identity: Identity | undefined): boolean {
  if (!identity) return false;
  if (identity.privileged) return true;
  return /admin|administrator|superuser|root|staff|owner/i.test(identity.role ?? "");
}

/** Return the markers from `source` that appear in `body`, case-insensitive. */
export function markersPresent(body: string, markers: string[]): string[] {
  const lower = body.toLowerCase();
  return markers.filter((m) => lower.includes(m.toLowerCase()));
}
