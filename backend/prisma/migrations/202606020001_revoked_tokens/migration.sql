-- Revoked JWT registry (SQLite). See migration.postgresql.sql / migration.mysql.sql
-- for the provider-flavored variants used during non-SQLite bootstrap reference.

-- CreateTable
CREATE TABLE "RevokedToken" (
    "jti" TEXT NOT NULL PRIMARY KEY,
    "user_id" TEXT,
    "expires_at" DATETIME NOT NULL,
    "revoked_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE INDEX "RevokedToken_expires_at_idx" ON "RevokedToken"("expires_at");
