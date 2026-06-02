-- Revoked JWT registry (MySQL / MariaDB).
-- Non-SQLite bootstrap currently uses `prisma db push` against a provider-rewritten
-- schema, so this file is the canonical SQL reference for MySQL deployments
-- and may be replayed manually if a migration-based workflow is adopted.

-- CreateTable
CREATE TABLE `RevokedToken` (
    `jti` VARCHAR(191) NOT NULL,
    `user_id` VARCHAR(191) NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `revoked_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `RevokedToken_expires_at_idx`(`expires_at`),
    PRIMARY KEY (`jti`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
