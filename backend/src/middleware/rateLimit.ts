/**
 * Shared rate-limit middleware.
 *
 * Centralizes all per-IP rate limiters used across the app so they share a
 * single `keyGenerator` (the trust-aware `getClientIp` from utils) and a
 * single error shape. This keeps Caddy / Cloudflare deployments honest:
 * each real client falls into its own bucket instead of every request
 * collapsing onto the loopback peer (R5).
 *
 * Implementation note: the project did not pin `express-rate-limit` as a
 * dependency historically (see `auth.routes.ts`), so this module follows the
 * same try-require + in-memory fallback pattern. Both backends honor the
 * same `getClientIp` keying so the limiter behaves consistently regardless
 * of which path is taken at runtime.
 *
 * Error response (uniform across all limiters):
 *   HTTP 429
 *   { success: false, error: { code: "RATE_LIMITED", message: "..." } }
 *
 * Wiring of these limiters into routes is intentionally deferred to tasks
 * 7.3 (auth) and 7.4 (qq + webhook). This module only exposes the limiters.
 */

import type { Request, Response, NextFunction, RequestHandler } from "express";
import { getClientIp } from "../utils/clientIp";

interface RateLimitOptions {
  windowMs: number;
  max: number;
  message?: string;
}

const DEFAULT_MESSAGE = "Too many requests, please try again later.";

// Track every in-memory store so tests (and `resetRateLimiters`) can wipe state
// without needing handles to individual limiters.
const inMemoryStores: Array<Map<string, { count: number; resetTime: number }>> = [];

/**
 * Reset all in-memory limiter buckets. Intended for test isolation; harmless
 * when the express-rate-limit backend is in use (those instances keep their
 * own internal store).
 */
export function resetRateLimiters(): void {
  for (const store of inMemoryStores) {
    store.clear();
  }
}

function send429(res: Response, message: string): void {
  res.status(429).json({
    success: false,
    error: {
      code: "RATE_LIMITED",
      message,
    },
  });
}

/**
 * In-memory limiter used when `express-rate-limit` is not installed.
 * Keys by `getClientIp(req)` so it behaves identically to the package-backed
 * version in terms of bucketing.
 */
function createInMemoryLimiter(opts: RateLimitOptions): RequestHandler {
  const attempts = new Map<string, { count: number; resetTime: number }>();
  inMemoryStores.push(attempts);
  const message = opts.message ?? DEFAULT_MESSAGE;

  return (req: Request, res: Response, next: NextFunction): void => {
    const key = getClientIp(req);
    const now = Date.now();
    const record = attempts.get(key);

    if (!record || now > record.resetTime) {
      attempts.set(key, { count: 1, resetTime: now + opts.windowMs });
      next();
      return;
    }

    if (record.count >= opts.max) {
      send429(res, message);
      return;
    }

    record.count++;
    next();
  };
}

/**
 * Build a rate limiter using `express-rate-limit` if available, otherwise
 * fall back to the in-memory implementation. Both code paths use the same
 * `getClientIp`-based key generator and the same `RATE_LIMITED` 429 shape.
 */
function createRateLimiter(opts: RateLimitOptions): RequestHandler {
  const message = opts.message ?? DEFAULT_MESSAGE;

  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const rl = require("express-rate-limit");
    return rl({
      windowMs: opts.windowMs,
      max: opts.max,
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req: Request) => getClientIp(req),
      handler: (_req: Request, res: Response) => send429(res, message),
    }) as RequestHandler;
  } catch {
    return createInMemoryLimiter(opts);
  }
}

// ---------------------------------------------------------------------------
// Concrete limiters
//
// Window / max values for `authRateLimiter` and `registerRateLimit` mirror
// the constants previously inlined in `auth.routes.ts` (15min/10 and 1h/5).
// QQ webhook / route limits are scoped tighter on a 60s window since these
// endpoints are exclusively driven by the bot bridge and have no legitimate
// burst use case from end users.
// ---------------------------------------------------------------------------

/** Auth-style endpoints (login, password reset, etc.): 10 requests / 15 minutes. */
export const authRateLimiter: RequestHandler = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: DEFAULT_MESSAGE,
});

/** Registration: 5 attempts / hour. */
export const registerRateLimit: RequestHandler = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: "Too many registration attempts, please try again later.",
});

/** `/webhook/qq-verify`: 30 requests / minute. */
export const qqVerifyRateLimit: RequestHandler = createRateLimiter({
  windowMs: 60 * 1000,
  max: 30,
  message: "Too many verification attempts, please try again later.",
});

/** `/api/v1/qq/*`: 60 requests / minute (slightly looser than webhook). */
export const qqRouteRateLimit: RequestHandler = createRateLimiter({
  windowMs: 60 * 1000,
  max: 60,
  message: DEFAULT_MESSAGE,
});
