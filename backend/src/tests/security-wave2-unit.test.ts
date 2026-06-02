import jwt from "jsonwebtoken";
import { FileType, TaskRole } from "@prisma/client";
import { createTestProject, createTestUser } from "./setup";
import { validateUpload } from "../modules/file/file.service";
import { verifyToken } from "../utils/jwt";
import { DEFAULT_EXTENSION_ALLOWLIST } from "../utils/defaultUploadPolicy";

describe("Security Remediation Wave 2", () => {
  describe("JWT algorithm enforcement", () => {
    const claims = {
      userId: "00000000-0000-0000-0000-000000000001",
      username: "algorithm_probe",
      role: "member",
      jti: "00000000-0000-4000-8000-000000000001",
    };

    it("rejects alg=none tokens", () => {
      const token = jwt.sign(claims, "", { algorithm: "none" });

      expect(() => verifyToken(token)).toThrow();
    });

    it("rejects HMAC tokens signed with a non-HS256 algorithm", () => {
      const token = jwt.sign(claims, process.env.JWT_SECRET!, {
        algorithm: "HS384",
      });

      expect(() => verifyToken(token)).toThrow();
    });
  });

  describe("validateUpload extension invariants", () => {
    async function makeProject() {
      const { user } = await createTestUser({ role: "supervisor" });
      const project = await createTestProject({ owner_id: user.id });
      return project;
    }

    function fileFor(extension: string, mimetype = "application/octet-stream") {
      return {
        originalname: `sample${extension}`,
        mimetype,
        size: 1024,
      };
    }

    it("only accepts uploads whose extension is in the effective allowlist", async () => {
      const project = await makeProject();
      const samples = [
        { extension: ".ass", mimetype: "application/x-ass", taskRole: TaskRole.translation },
        { extension: ".srt", mimetype: "application/srt", taskRole: TaskRole.timing },
        { extension: ".ttf", mimetype: "font/ttf", taskRole: TaskRole.post_production },
        { extension: ".zip", mimetype: "application/zip", taskRole: TaskRole.source },
        { extension: ".mp4", mimetype: "video/mp4", taskRole: TaskRole.encoding },
      ];

      for (const sample of samples) {
        const result = await validateUpload(
          fileFor(sample.extension, sample.mimetype),
          project.id,
          "supervisor",
          { taskRole: sample.taskRole }
        );

        expect(DEFAULT_EXTENSION_ALLOWLIST.has(sample.extension)).toBe(true);
        expect(result).toEqual({ valid: true });
      }
    });

    it("rejects extensions outside the allowlist even when MIME looks allowed", async () => {
      const project = await makeProject();
      const bypassAttempts = [
        { extension: ".html", mimetype: "text/plain", taskRole: TaskRole.translation },
        { extension: ".svg", mimetype: "application/xml", taskRole: TaskRole.translation },
        { extension: ".bin", mimetype: "video/mp4", taskRole: TaskRole.encoding },
        { extension: ".unknown", mimetype: "application/x-ass", taskRole: TaskRole.translation },
      ];

      for (const attempt of bypassAttempts) {
        const result = await validateUpload(
          fileFor(attempt.extension, attempt.mimetype),
          project.id,
          "supervisor",
          { taskRole: attempt.taskRole }
        );

        expect(DEFAULT_EXTENSION_ALLOWLIST.has(attempt.extension)).toBe(false);
        expect(result.valid).toBe(false);
        expect(result.error).toContain("not allowed");
      }
    });

    it("rejects .html and .svg while accepting .ass and role-appropriate .mp4", async () => {
      const project = await makeProject();

      await expect(
        validateUpload(fileFor(".html", "text/html"), project.id, "supervisor", {
          taskRole: TaskRole.translation,
          fileType: FileType.subtitle,
        })
      ).resolves.toMatchObject({ valid: false });

      await expect(
        validateUpload(fileFor(".svg", "image/svg+xml"), project.id, "supervisor", {
          taskRole: TaskRole.translation,
          fileType: FileType.subtitle,
        })
      ).resolves.toMatchObject({ valid: false });

      await expect(
        validateUpload(fileFor(".ass", "application/x-ass"), project.id, "supervisor", {
          taskRole: TaskRole.translation,
          fileType: FileType.subtitle,
        })
      ).resolves.toEqual({ valid: true });

      await expect(
        validateUpload(fileFor(".mp4", "video/mp4"), project.id, "supervisor", {
          taskRole: TaskRole.encoding,
          fileType: FileType.video,
        })
      ).resolves.toEqual({ valid: true });
    });
  });
});
