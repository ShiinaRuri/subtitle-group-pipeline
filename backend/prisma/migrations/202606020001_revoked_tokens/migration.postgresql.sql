-- Revoked JWT registry (PostgreSQL).
-- Non-SQLite bootstrap currently uses `prisma db push` against a provider-rewritten
-- schema, so this file is the canonical SQL reference for PostgreSQL deployments
-- and may be replayed manually if a migration-based workflow is adopted.

-- CreateTable
CREATE TABLE "RevokedToken" (
    "jti" TEXT NOT NULL,
    "user_id" TEXT,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "revoked_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RevokedToken_pkey" PRIMARY KEY ("jti")
);

-- CreateIndex
CREATE INDEX "RevokedToken_expires_at_idx" ON "RevokedToken"("expires_at");
