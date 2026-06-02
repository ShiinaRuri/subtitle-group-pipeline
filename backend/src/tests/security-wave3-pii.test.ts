import type { Application } from "express";
import { createApp } from "../app";
import { createTestUser } from "./setup";
import { get, expectSuccess } from "./helpers";
import * as authService from "../modules/auth/auth.service";

describe("Security Remediation Wave 3 PII minimization", () => {
  let app: Application;

  beforeAll(() => {
    app = createApp({ databaseReady: true });
  });

  function expectNoUserPii(items: Array<Record<string, unknown>>) {
    for (const item of items) {
      expect(item).not.toHaveProperty("email");
      expect(item).not.toHaveProperty("qq_number");
    }
  }

  it("omits email and QQ number for non-privileged auth user listings", async () => {
    const member = await createTestUser({ role: "member" });
    await createTestUser({
      username: "pii_target_member_scope",
      email: "pii-target-member@example.com",
      qq_number: "901234567",
    });

    const res = await get(app, "/api/v1/auth/users", member.token);

    expectSuccess(res, 200);
    expectNoUserPii(res.body.data.items);
  });

  it("omits email and QQ number for non-privileged root-level user aliases", async () => {
    const member = await createTestUser({ role: "member" });
    await createTestUser({
      username: "pii_target_root_scope",
      email: "pii-target-root@example.com",
      qq_number: "912345678",
    });

    const res = await get(app, "/api/v1/users", member.token);

    expectSuccess(res, 200);
    expectNoUserPii(res.body.data.items);
  });

  it("returns PII fields for privileged user listings", async () => {
    const admin = await createTestUser({ role: "super_admin" });
    const target = await createTestUser({
      username: "pii_target_admin_scope",
      email: "pii-target-admin@example.com",
      qq_number: "923456789",
    });

    const res = await get(app, "/api/v1/auth/users", admin.token);

    expectSuccess(res, 200);
    const item = res.body.data.items.find(
      (user: Record<string, unknown>) => user.id === target.user.id
    );
    expect(item).toMatchObject({
      email: "pii-target-admin@example.com",
      qq_number: "923456789",
    });
  });

  it("fails closed when requester role is missing", async () => {
    await createTestUser({
      username: "pii_target_missing_role",
      email: "pii-target-missing-role@example.com",
      qq_number: "934567890",
    });

    const users = await authService.getAllUsers(undefined);

    expectNoUserPii(users as Array<Record<string, unknown>>);
  });
});
