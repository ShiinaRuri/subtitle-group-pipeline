import request from "supertest";
import { createApp } from "../app";

describe("Security Remediation Wave 6 logging", () => {
  it("redacts download tokens from access logs", async () => {
    const app = createApp({ databaseReady: true });
    const rawToken = "raw-download-token-wave6-secret";
    const output: string[] = [];
    const writeSpy = jest
      .spyOn(process.stdout, "write")
      .mockImplementation((chunk: string | Uint8Array) => {
        output.push(String(chunk));
        return true;
      });

    try {
      await request(app).get(`/download/${rawToken}?preview=false`);
    } finally {
      writeSpy.mockRestore();
    }

    const log = output.join("");
    expect(log).toContain("/download/[REDACTED]?preview=false");
    expect(log).not.toContain(rawToken);
  });
});
