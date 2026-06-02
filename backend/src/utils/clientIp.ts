/**
 * Client IP resolution utilities.
 *
 * Goal: when the request arrives behind a trusted reverse proxy chain
 * (Cloudflare → Caddy → Express in this project), derive the *real* client IP
 * without trusting headers from arbitrary sources.
 *
 * Trust model:
 *   - We only honor `cf-connecting-ip` / `true-client-ip` when the request's
 *     immediate socket peer (`req.socket.remoteAddress`) is itself a member of
 *     a configured trusted-proxy CIDR allowlist. Any direct connection from an
 *     untrusted source is treated as forging those headers and ignored.
 *   - When the peer is not trusted, we fall back to `req.ip`, which Express
 *     resolves according to `app.set('trust proxy', ...)`.
 *
 * The CIDR list is sourced from `env.TRUSTED_PROXY_CIDRS` (added in task 7.1).
 * For forward compatibility while task 7.1 lands in parallel, this module also
 * reads `process.env.TRUSTED_PROXY_CIDRS` as a comma-separated fallback.
 *
 * Pure module: no side effects on import. CIDR parsing happens lazily on first
 * call, and is cached keyed by the raw CIDR source string.
 */

import net from "net";
import type { Request } from "express";
import { env } from "../config/env";

type IpFamily = "ipv4" | "ipv6";

/**
 * Resolve the configured trusted-proxy CIDRs.
 *
 * Prefers `env.TRUSTED_PROXY_CIDRS` (populated by task 7.1) and falls back to
 * `process.env.TRUSTED_PROXY_CIDRS` while that work is in flight. Accepts
 * either a comma-separated string or a string array.
 */
function getTrustedProxyCidrs(): string[] {
  const fromEnv = (env as unknown as { TRUSTED_PROXY_CIDRS?: string | string[] })
    .TRUSTED_PROXY_CIDRS;
  const raw = fromEnv ?? process.env.TRUSTED_PROXY_CIDRS ?? "";

  const entries = Array.isArray(raw) ? raw : raw.split(",");
  return entries.map((entry) => entry.trim()).filter((entry) => entry.length > 0);
}

let cachedCidrSource: string | undefined;
let cachedBlockList: net.BlockList | undefined;

function buildBlockList(cidrs: string[]): net.BlockList {
  const list = new net.BlockList();

  for (const entry of cidrs) {
    const [addr, prefixPart] = entry.split("/");
    if (!addr) continue;

    let family: IpFamily;
    if (net.isIPv4(addr)) {
      family = "ipv4";
    } else if (net.isIPv6(addr)) {
      family = "ipv6";
    } else {
      // Skip malformed entries instead of crashing the request path.
      continue;
    }

    const defaultPrefix = family === "ipv4" ? 32 : 128;
    let prefix = defaultPrefix;
    if (prefixPart !== undefined) {
      const parsed = Number.parseInt(prefixPart, 10);
      if (!Number.isInteger(parsed) || parsed < 0 || parsed > defaultPrefix) {
        continue;
      }
      prefix = parsed;
    }

    try {
      if (prefix === defaultPrefix) {
        list.addAddress(addr, family);
      } else {
        list.addSubnet(addr, prefix, family);
      }
    } catch {
      // Defensive: any rejection from BlockList just drops that entry.
    }
  }

  return list;
}

function getBlockList(): net.BlockList {
  const cidrs = getTrustedProxyCidrs();
  // Cache key is the literal source — survives unchanged config across calls
  // and rebuilds automatically if the underlying env changes (e.g., in tests).
  const source = cidrs.join(",");
  if (cachedCidrSource !== source || !cachedBlockList) {
    cachedCidrSource = source;
    cachedBlockList = buildBlockList(cidrs);
  }
  return cachedBlockList;
}

/**
 * Normalize an address for BlockList lookup.
 *
 * Node represents incoming IPv4 connections on dual-stack sockets as
 * `::ffff:1.2.3.4`. We strip the IPv4-mapped prefix so a CIDR like
 * `127.0.0.0/8` matches `::ffff:127.0.0.1`.
 */
function normalizeAddress(
  addr: string,
): { value: string; family: IpFamily } | null {
  if (!addr) return null;

  if (addr.startsWith("::ffff:")) {
    const v4 = addr.slice("::ffff:".length);
    if (net.isIPv4(v4)) {
      return { value: v4, family: "ipv4" };
    }
  }

  if (net.isIPv4(addr)) return { value: addr, family: "ipv4" };
  if (net.isIPv6(addr)) return { value: addr, family: "ipv6" };
  return null;
}

/**
 * Returns true when `remote` falls within the configured trusted-proxy
 * allowlist. Returns false for unknown / unparsable input — fail closed.
 */
export function isTrustedProxy(remote: string | undefined | null): boolean {
  if (!remote) return false;
  const normalized = normalizeAddress(remote);
  if (!normalized) return false;
  return getBlockList().check(normalized.value, normalized.family);
}

function pickHeader(value: string | string[] | undefined): string | undefined {
  if (!value) return undefined;
  // Pick the first occurrence if a header is repeated; reject array forms
  // beyond the first to avoid attacker-injected duplicates being preferred.
  const first = Array.isArray(value) ? value[0] : value;
  if (typeof first !== "string") return undefined;
  const trimmed = first.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Derive the real client IP for the given request.
 *
 * Priority when the immediate socket peer is a trusted proxy:
 *   1. `cf-connecting-ip` (Cloudflare)
 *   2. `true-client-ip`   (Cloudflare Enterprise / Akamai)
 *
 * Otherwise (or when none of the above are present) falls back to `req.ip`,
 * which Express resolves per `app.set('trust proxy', ...)`. Returns the
 * literal `"unknown"` if no IP can be determined, matching existing rate-limit
 * key conventions in this codebase.
 */
export function getClientIp(req: Request): string {
  const remote = req.socket?.remoteAddress;

  if (isTrustedProxy(remote)) {
    const cf = pickHeader(req.headers["cf-connecting-ip"]);
    if (cf) return cf;

    const tci = pickHeader(req.headers["true-client-ip"]);
    if (tci) return tci;
  }

  return req.ip || "unknown";
}
