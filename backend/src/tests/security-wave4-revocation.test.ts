import type { Application } from "express";
import request from "supertest";
import { decode } from "jsonwebtoken";
import { createApp } from "../app";
import { createTestUser, prisma } from "./setup";
import { get, post, expectError, expectSuccess } from "./helpers";
import { cleanupExpiredRevokedTokenEntries } from "../jobs/revoked-token.cleanup";
import { signToken } from "../utils/jwt";

describe("Security Remediation Wave 4", () => {
  let app: Application;

  beforeAll(() => {
    app = createApp({ databaseReady: true });
  });

  describe("JWT revocation", () => {
    it("revokes the current access token immediately on logout", async () => {
      const user = await createTestUser();

      const logoutRes = await post(app, "/api/v1/auth/logout", {}, user.token);
      expectSuccess(logoutRes, 200);

      const meRes = await get(app, "/api/v1/auth/me", user.token);
      expectError(meRes, 401, "UNAUTHORIZED");

      const payload = decode(user.token) as { jti?: string } | null;
      expect(payload?.jti).toBeDefined();
      await expect(
        prisma.revokedToken.findUnique({ where: { jti: payload!.jti! } })
      ).resolves.toBeTruthy();
    });

    it("keeps revoked tokens rejected across repeated authentication attempts", async () => {
      const user = await createTestUser();
      await post(app, "/api/v1/auth/logout", {}, user.token);

      for (let i = 0; i < 3; i++) {
        const res = await get(app, "/api/v1/auth/me", user.token);
        expectError(res, 401, "UNAUTHORIZED");
      }
    });

    it("rotates refresh tokens by revoking the old refresh token", async () => {
      const user = await createTestUser();

      const first = await post(app, "/api/v1/auth/refresh", {
        refreshToken: user.refreshToken,
      });
      expectSuccess(first, 200);

      const second = await post(app, "/api/v1/auth/refresh", {
        refreshToken: user.refreshToken,
      });
      expectError(second, 401, "UNAUTHORIZED");

      const rotated = await post(app, "/api/v1/auth/refresh", {
        refreshToken: first.body.data.refreshToken,
      });
      expectSuccess(rotated, 200);
    });

    it("cleans up expired revocation entries", async () => {
      await prisma.revokedToken.createMany({
        data: [
          {
            jti: "expired-wave4-token",
            user_id: null,
            expires_at: new Date(Date.now() - 1000),
          },
          {
            jti: "active-wave4-token",
            user_id: null,
            expires_at: new Date(Date.now() + 60_000),
          },
        ],
      });

      await cleanupExpiredRevokedTokenEntries();

      await expect(
        prisma.revokedToken.findUnique({ where: { jti: "expired-wave4-token" } })
      ).resolves.toBeNull();
      await expect(
        prisma.revokedToken.findUnique({ where: { jti: "active-wave4-token" } })
      ).resolves.toBeTruthy();
    });
  });

  describe("sensitive endpoint rate limiting", () => {
    it("rate-limits the QQ verification webhook per trusted client IP bucket", async () => {
      const payload = {
        message: "/verify RATE1234",
        group_id: "123456789",
        user_id: "123123123",
      };

      for (let i = 0; i < 30; i++) {
        const res = await request(app)
          .post("/webhook/qq-verify")
          .set("CF-Connecting-IP", "198.51.100.40")
          .send(payload);
        expect(res.status).not.toBe(429);
      }

      const limited = await request(app)
        .post("/webhook/qq-verify")
        .set("CF-Connecting-IP", "198.51.100.40")
        .send(payload);
      expectError(limited, 429, "RATE_LIMITED");

      const otherBucket = await request(app)
        .post("/webhook/qq-verify")
        .set("CF-Connecting-IP", "198.51.100.41")
        .send(payload);
      expect(otherBucket.status).not.toBe(429);
    });

    it("rate-limits QQ API routes", async () => {
      for (let i = 0; i < 60; i++) {
        const res = await request(app)
          .post("/api/v1/qq/heartbeat")
          .set("CF-Connecting-IP", "198.51.100.50")
          .send({});
        expect(res.status).not.toBe(429);
      }

      const limited = await request(app)
        .post("/api/v1/qq/heartbeat")
        .set("CF-Connecting-IP", "198.51.100.50")
        .send({});
      expectError(limited, 429, "RATE_LIMITED");
    });
  });

  describe("PII non-disclosure invariant", () => {
    it("never returns email or QQ number for non-privileged roles", async () => {
      const roles = ["member", "unknown", "", undefined] as Array<string | undefined>;
      await createTestUser({
        username: "wave4_pii_target",
        email: "wave4-pii-target@example.com",
        qq_number: "944444444",
      });

      for (const role of roles) {
        const token = signToken({
          userId: `00000000-0000-4000-8000-${Math.random().toString().slice(2, 14).padEnd(12, "0")}`,
          username: "wave4_non_privileged_probe",
          role: role ?? "member",
        });
        const payload = decode(token) as { role: string };
        const users = await import("../modules/auth/auth.service").then((module) =>
          module.getAllUsers(payload.role)
        );

        for (const user of users as Array<Record<string, unknown>>) {
          expect(user).not.toHaveProperty("email");
          expect(user).not.toHaveProperty("qq_number");
        }
      }
    });
  });
});
