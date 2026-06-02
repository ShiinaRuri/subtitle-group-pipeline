import { Request } from "express";
import { AppError } from "../../utils/response";
import * as systemService from "../system/system.service";

/**
 * Validates the QQ bridge token (Bearer) on incoming requests.
 *
 * Behavior (kept identical to the previous inline implementation in qq.controller.ts):
 * - When no bridge secret is configured, validation is skipped (allow-through).
 * - When a secret is configured, the Authorization header MUST be `Bearer <secret>`,
 *   otherwise this throws `AppError("Invalid QQ bridge token", "UNAUTHORIZED", 401)`.
 *
 * Extracted into its own module so it can be reused by both the QQ HTTP routes
 * and the public `/webhook/qq-verify` handler (see Requirement 2 / R2).
 */
export async function ensureBridgeToken(req: Request): Promise<void> {
  const settings = await systemService.getQqBridgeRuntimeSettings();
  if (!settings.secret) return;

  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (token !== settings.secret) {
    throw new AppError("Invalid QQ bridge token", "UNAUTHORIZED", 401);
  }
}
