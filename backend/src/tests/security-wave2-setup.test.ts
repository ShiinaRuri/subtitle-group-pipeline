import { PrismaClient } from "@prisma/client";
import fs from "fs";
import os from "os";
import path from "path";
import type { CompleteSetupInput } from "../modules/setup/setup.schema";

const SETUP_SERVICE_PATH = path.resolve(
  process.cwd(),
  "src/modules/setup/setup.service.ts"
);
const SETUP_TEST_ENV_PATH = path.join(
  os.tmpdir(),
  `subtitle-group-pipeline-wave2-setup-${process.pid}.env`
);
const SETUP_TEST_DB_PATH = path.join(
  os.tmpdir(),
  `subtitle-group-pipeline-wave2-setup-${process.pid}.db`
);

function sqliteFileUrl(filePath: string): string {
  return `file:${filePath.replace(/\\/g, "/")}`;
}

function makeSetupInput(databaseUrl: string): CompleteSetupInput {
  return {
    database: {
      provider: "sqlite",
      url: databaseUrl,
    },
    security: {
      jwt_secret: "wave2-setup-jwt-secret-with-at-least-32-chars",
    },
    admin: {
      username: "admin_sql_meta",
      password: "InitialPassword123!",
      nickname: "Admin'); DROP TABLE \"User\"; --",
      email: "admin.sql-meta@example.com",
    },
    storage: {
      name: "Local'); DROP TABLE \"StorageBackend\"; --",
      backend_type: "local",
      config: JSON.stringify({
        basePath: "./uploads/wave2'); DROP TABLE \"User\"; --",
      }),
      quota_bytes: null,
    },
  };
}

describe("Security Remediation Wave 2 setup bootstrap", () => {
  const originalEnvFilePath = process.env.ENV_FILE_PATH;
  const originalDatabaseUrl = process.env.DATABASE_URL;
  const originalJwtSecret = process.env.JWT_SECRET;

  beforeAll(() => {
    process.env.ENV_FILE_PATH = SETUP_TEST_ENV_PATH;
  });

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

  it("does not contain the retired manual SQL bootstrap path", () => {
    const source = fs.readFileSync(SETUP_SERVICE_PATH, "utf8");

    expect(source).not.toMatch(/\bbuildBootstrapSql\b/);
    expect(source).not.toMatch(/\bexecuteSql\b/);
    expect(source).not.toMatch(/\bsqlString\b/);
    expect(source).not.toMatch(/function\s+\w*Bootstrap\w*\s*\([^)]*\)\s*{[\s\S]*?\$executeRawUnsafe/i);
  });

  it("bootstraps SQLite with SQL metacharacters as literal admin and storage values", async () => {
    const databaseUrl = sqliteFileUrl(SETUP_TEST_DB_PATH);
    const { completeSetup } = await import("../modules/setup/setup.service");

    const result = await completeSetup(makeSetupInput(databaseUrl));

    expect(result).toMatchObject({
      initialized: true,
      restartRequired: false,
      admin: {
        username: "admin_sql_meta",
        nickname: "Admin'); DROP TABLE \"User\"; --",
        email: "admin.sql-meta@example.com",
        role: "super_admin",
        status: "active",
      },
      storage: {
        name: "Local'); DROP TABLE \"StorageBackend\"; --",
        backend_type: "local",
        is_default: true,
        is_active: true,
      },
    });

    const client = new PrismaClient({
      datasources: {
        db: { url: databaseUrl },
      },
    });

    try {
      await client.$connect();
      const [admin, storage, migrationCount] = await Promise.all([
        client.user.findUniqueOrThrow({
          where: { username: "admin_sql_meta" },
          select: {
            username: true,
            nickname: true,
            email: true,
            role: true,
          },
        }),
        client.storageBackend.findFirstOrThrow({
          where: { is_default: true, is_active: true },
          select: {
            name: true,
            backend_type: true,
            config: true,
          },
        }),
        client.$queryRaw<Array<{ count: bigint | number }>>`
          SELECT COUNT(*) AS count FROM "_prisma_migrations"
        `,
      ]);

      expect(admin).toEqual({
        username: "admin_sql_meta",
        nickname: "Admin'); DROP TABLE \"User\"; --",
        email: "admin.sql-meta@example.com",
        role: "super_admin",
      });
      expect(storage.name).toBe("Local'); DROP TABLE \"StorageBackend\"; --");
      expect(JSON.parse(storage.config)).toEqual({
        basePath: "./uploads/wave2'); DROP TABLE \"User\"; --",
      });
      expect(Number(migrationCount[0]?.count ?? 0)).toBeGreaterThan(0);

      await expect(client.user.count()).resolves.toBe(1);
      await expect(client.storageBackend.count()).resolves.toBe(1);
    } finally {
      await client.$disconnect();
    }
  });
});
