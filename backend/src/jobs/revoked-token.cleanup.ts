import { cleanupExpiredRevokedTokens } from "../modules/auth/auth.service";

/**
 * Job: Revoked JWT Cleanup
 * Removes revocation-list entries after their original token expiry so the
 * blacklist cannot grow forever.
 */
export async function cleanupExpiredRevokedTokenEntries(): Promise<void> {
  const result = await cleanupExpiredRevokedTokens();
  if (result.deletedCount > 0) {
    console.log(`[RevokedTokenCleanupJob] Deleted ${result.deletedCount} expired token(s)`);
  }
}
