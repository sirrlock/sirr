/**
 * Pure helper functions extracted for testability.
 */

/**
 * Parse a secret key reference from natural language.
 *   "sirr:KEYNAME"   → "KEYNAME"
 *   "KEYNAME#server" → "KEYNAME"
 *   "KEYNAME"        → "KEYNAME"
 */
export function parseKeyRef(ref: string): string {
  if (ref.startsWith("sirr:")) return ref.slice(5);
  if (ref.includes("#")) return ref.split("#")[0]!;
  return ref.trim();
}

/**
 * Format a Unix timestamp (seconds) as a human-readable TTL string
 * relative to now. Returns "no expiry" for null, "expired" for past timestamps.
 */
export function formatTtl(expiresAt: number | null): string {
  if (expiresAt === null) return "no expiry";
  const now = Math.floor(Date.now() / 1000);
  const secs = expiresAt - now;
  if (secs <= 0) return "expired";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
}
