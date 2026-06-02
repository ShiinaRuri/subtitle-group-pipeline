import type { Request } from "express";
import { PrismaClient } from "@prisma/client";
import fs from "fs";
import os from "os";
import path from "path";
import { getClientIp } from "../utils/clientIp";
import { requestPasswordReset } from "../modules/auth/auth.service";
import { createTestStorageBackend, createTestUser, prisma } from "./setup";
import type { CompleteSetupInput } from "../modules/setup/setup.schema";

const BASE62_CODE = /^[A-Za-z0-9]{8}$/;
const SETUP_TEST_ENV_PATH = path.join(
  os.tmpdir(),
  `subtitle-group-pipeline-setup-${process.pid}.env`
);
const SETUP_TEST_DB_PATH = path.join(
  os.tmpdir(),
  `subtitle-group-pipeline-setup-${process.pid}.db`
);
type SetupInputOverrides = {
  database?: Partial<CompleteSetupInput["database"]>;
  security?: Partial<CompleteSetupInput["security"]>;
  admin?: Partial<CompleteSetupInput["admin"]>;
  storage?: Partial<CompleteSetupInput["storage"]>;
};

function makeRequest(params: {
  remoteAddress?: string;
  headers?: Request["headers"];
  ip?: string;
}): Request {
  return {
    headers: params.headers ?? {},
    ip: params.ip,
    socket: {
      remoteAddress: params.remoteAddress,
    },
  } as Request;
}

describe("Security Remediation Wave 1", () => {
  describe("getClientIp trusted proxy handling", () => {
    it("honors cf-connecting-ip only when the immediate remote is trusted", () => {
      const req = makeRequest({
        remoteAddress: "173.245.48.42",
        ip: "10.0.0.10",
        headers: {
          "cf-connecting-ip": "198.51.100.7",
          "true-client-ip": "198.51.100.8",
        },
      });

      expect(getClientIp(req)).toBe("198.51.100.7");
    });

    it("honors true-client-ip from a trusted remote when Cloudflare header is absent", () => {
      const req = makeRequest({
        remoteAddress: "2606:4700::7",
        ip: "10.0.0.10",
        headers: {
          "true-client-ip": "198.51.100.9",
        },
      });

      expect(getClientIp(req)).toBe("198.51.100.9");
    });

    it("ignores forged proxy headers from an untrusted remote and falls back to req.ip", () => {
      const req = makeRequest({
        remoteAddress: "198.51.100.200",
        ip: "10.0.0.10",
        headers: {
          "cf-connecting-ip": "203.0.113.250",
          "true-client-ip": "203.0.113.251",
        },
      });

      expect(getClientIp(req)).toBe("10.0.0.10");
    });
  });

  describe("verification code invariants", () => {
    async function createPasswordResetCode(username: string): Promise<string> {
      await requestPasswordReset(username);
      const challenge = await prisma.verificationChallenge.findFirstOrThrow({
        where: {
          code: { startsWith: "PWD:" },
          used_at: null,
        },
        orderBy: { created_at: "desc" },
      });

      return challenge.code.replace(/^PWD:/, "");
    }

    it("generates 8-character base62 password reset codes across repeated samples", async () => {
      for (let i = 0; i < 20; i++) {
        const { user } = await createTestUser({
          username: `reset_sample_${i}`,
        });
        await prisma.user.update({
          where: { id: user.id },
          data: { email: null, qq_number: null },
        });

        const code = await createPasswordResetCode(user.username);

        expect(code).toHaveLength(8);
        expect(code).toMatch(BASE62_CODE);
      }
    });

    it("does not depend on Math.random for password reset code generation", async () => {
      const { user } = await createTestUser({
        username: "reset_without_math_random",
      });
      await prisma.user.update({
        where: { id: user.id },
        data: { email: null, qq_number: null },
      });
      jest.spyOn(Math, "random").mockImplementation(() => {
        throw new Error("Math.random must not be used for verification codes");
      });

      const code = await createPasswordResetCode(user.username);

      expect(code).toHaveLength(8);
      expect(code).toMatch(BASE62_CODE);
    });
  });

  describe("setup initialized guard", () => {
    const originalEnvFilePath = process.env.ENV_FILE_PATH;
    const originalDatabaseUrl = process.env.DATABASE_URL;
    const originalJwtSecret = process.env.JWT_SECRET;

    beforeAll(() => {
      process.env.ENV_FILE_PATH = SETUP_TEST_ENV_PATH;
    });

    function sqliteFileUrl(filePath: string): string {
      return `file:${filePath.replace(/\\/g, "/")}`;
    }

    async function countBootstrappedRecords(databaseUrl: string) {
      const client = new PrismaClient({
        datasources: { db: { url: databaseUrl } },
      });
      try {
        await client.$connect();
        const [adminCount, defaultStorageCount] = await Promise.all([
          client.user.count({ where: { role: "super_admin" } }),
          client.storageBackend.count({
            where: { is_default: true, is_active: true },
          }),
        ]);
        return { adminCount, defaultStorageCount };
      } finally {
        await client.$disconnect();
      }
    }

    afterEach(async () => {
      process.env.DATABASE_URL = originalDatabaseUrl;
      if (originalJwtSecret === undefined) {
        delete process.env.JWT_SECRET;
      } else {
        process.env.JWT_SECRET = originalJwtSecret;
      }
      if (originalDatabaseUrl) {
        const { configurePrisma } = await import("../config/database");
        await configurePrisma(originalDatabaseUrl);
      }
      fs.rmSync(SETUP_TEST_ENV_PATH, { force: true });
      fs.rmSync(SETUP_TEST_DB_PATH, { force: true });
    });

    afterAll(() => {
      if (originalEnvFilePath === undefined) {
        delete process.env.ENV_FILE_PATH;
      } else {
        process.env.ENV_FILE_PATH = originalEnvFilePath;
      }
      fs.rmSync(SETUP_TEST_ENV_PATH, { force: true });
      fs.rmSync(SETUP_TEST_DB_PATH, { force: true });
    });

    function makeSetupInput(overrides: SetupInputOverrides = {}): CompleteSetupInput {
      return {
        database: {
          provider: "sqlite",
          url: process.env.DATABASE_URL || "file:./test.db",
          ...overrides.database,
        },
        security: {
          jwt_secret: "test-setup-jwt-secret-with-at-least-32-characters",
          ...overrides.security,
        },
        admin: {
          username: "initial_admin",
          password: "InitialPassword123!",
          nickname: "Initial Admin",
          email: "initial-admin@example.com",
          ...overrides.admin,
        },
        storage: {
          name: "Initial Local Storage",
          backend_type: "local",
          config: JSON.stringify({ basePath: "./uploads/setup-test" }),
          quota_bytes: null,
          ...overrides.storage,
        },
      };
    }

    it("throws ALREADY_INITIALIZED before provider validation or setup side effects", async () => {
      await createTestUser({
        username: "existing_super_admin",
        role: "super_admin",
      });
      await createTestStorageBackend({
        name: "Existing Default Storage",
        is_default: true,
        is_active: true,
      });

      const beforeAdminCount = await prisma.user.count({
        where: { role: "super_admin" },
      });
      const beforeDefaultStorageCount = await prisma.storageBackend.count({
        where: { is_default: true, is_active: true },
      });
      const { completeSetup } = await import("../modules/setup/setup.service");

      await expect(
        completeSetup(
          makeSetupInput({
            database: {
              provider: "sqlite",
              url: "postgresql://setup-guard-should-not-validate/provider",
            },
            storage: {
              config: "not-json-because-guard-must-run-first",
            },
          })
        )
      ).rejects.toMatchObject({
        code: "ALREADY_INITIALIZED",
        statusCode: 409,
      });

      await expect(
        prisma.user.count({ where: { role: "super_admin" } })
      ).resolves.toBe(beforeAdminCount);
      await expect(
        prisma.storageBackend.count({
          where: { is_default: true, is_active: true },
        })
      ).resolves.toBe(beforeDefaultStorageCount);
      expect(fs.existsSync(SETUP_TEST_ENV_PATH)).toBe(false);
      expect(process.env.DATABASE_URL).toBe(originalDatabaseUrl);
      expect(process.env.JWT_SECRET).toBe(originalJwtSecret);
    });

    it("allows first-time SQLite bootstrap when the system is uninitialized", async () => {
      const databaseUrl = sqliteFileUrl(SETUP_TEST_DB_PATH);
      const { completeSetup } = await import("../modules/setup/setup.service");
      const result = await completeSetup(
        makeSetupInput({
          database: {
            provider: "sqlite",
            url: databaseUrl,
          },
        })
      );

      expect(result).toMatchObject({
        initialized: true,
        restartRequired: false,
        admin: {
          username: "initial_admin",
          role: "super_admin",
          status: "active",
        },
        storage: {
          name: "Initial Local Storage",
          backend_type: "local",
          is_default: true,
          is_active: true,
        },
      });
      await expect(countBootstrappedRecords(databaseUrl)).resolves.toEqual({
        adminCount: 1,
        defaultStorageCount: 1,
      });
      expect(fs.readFileSync(SETUP_TEST_ENV_PATH, "utf8")).toContain(
        "DATABASE_URL="
      );
    });
  });
});
