import type { Application } from "express";
import request from "supertest";
import { createApp } from "../app";
import {
  createTestFile,
  createTestProject,
  createTestUser,
  prisma,
} from "./setup";
import { get, post, expectError, expectSuccess } from "./helpers";

describe("Security Wave 2 HTTP Coverage", () => {
  let app: Application;

  beforeAll(() => {
    app = createApp({ databaseReady: true });
  });

  describe("QQ verification webhook bridge token", () => {
    async function createPendingQQVerification() {
      await prisma.registrationPolicy.create({
        data: { mode: "qq_verification", qq_group_number: "123456789" },
      });
      await prisma.qqBridgeSettings.create({
        data: {
          enabled: true,
          endpoint: "http://127.0.0.1:9",
          secret: "bridge-secret",
        },
      });

      const registerRes = await post(app, "/api/v1/auth/register", {
        username: `wave2qq_${Math.random().toString(36).slice(2, 10)}`,
        password: "Password123!",
        nickname: "Wave 2 QQ",
        qq_number: "123123123",
      });
      expectSuccess(registerRes);

      const code = registerRes.body.data.copyReady as string;
      const userId = registerRes.body.data.user.id as string;
      return { code, userId };
    }

    async function expectVerificationStillPending(userId: string, code: string) {
      const [user, challenge] = await Promise.all([
        prisma.user.findUnique({ where: { id: userId } }),
        prisma.verificationChallenge.findUnique({ where: { code } }),
      ]);

      expect(user?.status).toBe("pending_verification");
      expect(challenge?.used_at).toBeNull();
      expect(challenge?.used_by).toBe(userId);
    }

    it("returns 401 and does not complete verification when bridge token is missing", async () => {
      const { code, userId } = await createPendingQQVerification();

      const res = await post(app, "/webhook/qq-verify", {
        message: `/verify ${code}`,
        group_id: "123456789",
        user_id: "123123123",
      });

      expectError(res, 401, "UNAUTHORIZED");
      await expectVerificationStillPending(userId, code);
    });

    it("rejects every command before downstream auth handlers when bridge token is missing", async () => {
      await prisma.qqBridgeSettings.create({
        data: {
          enabled: true,
          endpoint: "http://127.0.0.1:9",
          secret: "bridge-secret",
        },
      });
      const authService = await import("../modules/auth/auth.service");
      const verifyByQQ = jest.spyOn(authService, "verifyByQQ");
      const verifyPasswordResetByQQ = jest.spyOn(authService, "verifyPasswordResetByQQ");
      const verifyQQRebindByQQ = jest.spyOn(authService, "verifyQQRebindByQQ");
      const commands = [
        "/verify ABCD1234",
        "/resetpass ABCD1234",
        "/rebindqq-old ABCD1234",
        "/rebindqq-new ABCD1234",
      ];

      for (const message of commands) {
        const res = await post(app, "/webhook/qq-verify", {
          message,
          group_id: "123456789",
          user_id: "123123123",
        });
        expectError(res, 401, "UNAUTHORIZED");
      }

      expect(verifyByQQ).not.toHaveBeenCalled();
      expect(verifyPasswordResetByQQ).not.toHaveBeenCalled();
      expect(verifyQQRebindByQQ).not.toHaveBeenCalled();
    });

    it("returns 401 and does not complete verification when bridge token is wrong", async () => {
      const { code, userId } = await createPendingQQVerification();

      const res = await request(app)
        .post("/webhook/qq-verify")
        .set("Authorization", "Bearer wrong-secret")
        .send({
          message: `/verify ${code}`,
          group_id: "123456789",
          user_id: "123123123",
        });

      expectError(res, 401, "UNAUTHORIZED");
      await expectVerificationStillPending(userId, code);
    });

    it("allows verification when bridge token is correct", async () => {
      const { code, userId } = await createPendingQQVerification();

      const res = await request(app)
        .post("/webhook/qq-verify")
        .set("Authorization", "Bearer bridge-secret")
        .send({
          message: `/verify ${code}`,
          group_id: "123456789",
          user_id: "123123123",
        });

      expectSuccess(res, 200);
      expect(res.body.data.success).toBe(true);

      const [user, challenge] = await Promise.all([
        prisma.user.findUnique({ where: { id: userId } }),
        prisma.verificationChallenge.findUnique({ where: { code } }),
      ]);
      expect(user?.status).toBe("active");
      expect(challenge?.used_at).not.toBeNull();
      expect(challenge?.used_by).toBeNull();
    });

  });

  describe("Project and file authorization boundaries", () => {
    it("returns 403 instead of an empty list when a non-member lists project files", async () => {
      const owner = await createTestUser({ role: "supervisor" });
      const outsider = await createTestUser();
      const project = await createTestProject({ owner_id: owner.user.id });
      await createTestFile({ project_id: project.id, uploader_id: owner.user.id });

      const res = await get(app, `/api/v1/files?project_id=${project.id}`, outsider.token);

      expectError(res, 403, "FORBIDDEN");
      expect(res.body.data).toBeUndefined();
    });

    it("returns 403 instead of an empty list on project-scoped file listing aliases", async () => {
      const owner = await createTestUser({ role: "supervisor" });
      const outsider = await createTestUser();
      const project = await createTestProject({ owner_id: owner.user.id });
      await createTestFile({ project_id: project.id, uploader_id: owner.user.id });

      const res = await get(app, `/api/v1/files/projects/${project.id}/files`, outsider.token);

      expectError(res, 403, "FORBIDDEN");
      expect(res.body.data).toBeUndefined();
    });

    it("returns 403 when a non-member reads file metadata", async () => {
      const owner = await createTestUser({ role: "supervisor" });
      const outsider = await createTestUser();
      const project = await createTestProject({ owner_id: owner.user.id });
      const { file } = await createTestFile({
        project_id: project.id,
        uploader_id: owner.user.id,
      });

      const res = await get(app, `/api/v1/files/${file.id}`, outsider.token);

      expectError(res, 403, "FORBIDDEN");
      expect(res.body.data).toBeUndefined();
    });

    it("returns 403 when a non-member reads file versions", async () => {
      const owner = await createTestUser({ role: "supervisor" });
      const outsider = await createTestUser();
      const project = await createTestProject({ owner_id: owner.user.id });
      const { file } = await createTestFile({
        project_id: project.id,
        uploader_id: owner.user.id,
      });

      const res = await get(app, `/api/v1/files/${file.id}/versions`, outsider.token);

      expectError(res, 403, "FORBIDDEN");
      expect(res.body.data).toBeUndefined();
    });

    it("returns 401 for anonymous project list reads", async () => {
      const res = await get(app, "/api/v1/projects");

      expectError(res, 401, "UNAUTHORIZED");
    });

    it("returns 401 for anonymous project detail reads", async () => {
      const owner = await createTestUser({ role: "supervisor" });
      const project = await createTestProject({ owner_id: owner.user.id });

      const res = await get(app, `/api/v1/projects/${project.id}`);

      expectError(res, 401, "UNAUTHORIZED");
    });

    it("returns 401 for anonymous project members reads", async () => {
      const owner = await createTestUser({ role: "supervisor" });
      const project = await createTestProject({ owner_id: owner.user.id });

      const res = await get(app, `/api/v1/projects/${project.id}/members`);

      expectError(res, 401, "UNAUTHORIZED");
    });

    it("returns 403 when an authenticated non-member reads project detail", async () => {
      const owner = await createTestUser({ role: "supervisor" });
      const outsider = await createTestUser();
      const project = await createTestProject({ owner_id: owner.user.id });

      const res = await get(app, `/api/v1/projects/${project.id}`, outsider.token);

      expectError(res, 403, "FORBIDDEN");
    });

    it("returns 403 when an authenticated non-member reads project members", async () => {
      const owner = await createTestUser({ role: "supervisor" });
      const outsider = await createTestUser();
      const project = await createTestProject({ owner_id: owner.user.id });

      const res = await get(app, `/api/v1/projects/${project.id}/members`, outsider.token);

      expectError(res, 403, "FORBIDDEN");
    });
  });
});
