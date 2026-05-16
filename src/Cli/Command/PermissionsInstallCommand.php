<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Cli\Command;

use MonkeysLegion\Cli\Console\Attributes\Command as CommandAttr;
use MonkeysLegion\Cli\Console\Command;
use MonkeysLegion\Cli\Console\Traits\Cli;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Publishes permissions entities, config, and migration stubs
 * into the host application skeleton.
 *
 * Usage: php ml permissions:install
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
#[CommandAttr('permissions:install', 'Publish Permissions entities, config, and migrations into your project')]
final class PermissionsInstallCommand extends Command
{
    use Cli;

    protected function handle(): int
    {
        $projectRoot = $this->resolveProjectRoot();
        $packageRoot = dirname(__DIR__, 3);
        $published = 0;
        $skipped = 0;
        $failed = 0;

        $this->showHeader();

        // ── Step 1: Config ──────────────────────────────────────
        $this->cliLine()
            ->info('Step 1/3')->space()->muted('Publishing configuration')
            ->print();

        $configResult = $this->publishFile(
            "{$packageRoot}/config/permissions.mlc",
            "{$projectRoot}/config/permissions.mlc",
            $projectRoot,
        );
        $this->countResult($configResult, $published, $skipped, $failed);

        // ── Step 2: Entities ────────────────────────────────────
        $this->cliLine()->newline()->print();
        $this->cliLine()
            ->info('Step 2/3')->space()->muted('Publishing entity stubs to app/Entity/')
            ->print();

        $entities = [
            'Permission.php',
            'Role.php',
            'UserRole.php',
            'UserPermission.php',
            'StoredRule.php',
            'PermissionRequest.php',
            'RequestStatus.php',
            'RequestType.php',
        ];

        foreach ($entities as $entity) {
            $source = "{$packageRoot}/src/Entity/{$entity}";
            $target = "{$projectRoot}/app/Entity/{$entity}";

            $result = $this->publishFile($source, $target, $projectRoot);
            $this->countResult($result, $published, $skipped, $failed);
        }

        // ── Step 3: Migration ───────────────────────────────────
        $this->cliLine()->newline()->print();
        $this->cliLine()
            ->info('Step 3/3')->space()->muted('Generating migration stub')
            ->print();

        $migrationFile = $this->generateMigration($projectRoot);
        if ($migrationFile !== null) {
            $published++;
            $this->cliLine()
                ->success('✓ Generated migration')->space()
                ->add(str_replace($projectRoot . '/', '', $migrationFile), 'cyan')
                ->print();
        }

        // ── Summary ─────────────────────────────────────────────
        $this->cliLine()->newline()->print();
        $this->showSummary($published, $skipped, $failed);

        return self::SUCCESS;
    }

    // ── Internal ────────────────────────────────────────────────

    private function publishFile(string $source, string $target, string $projectRoot): string
    {
        if (!file_exists($source)) {
            $this->cliLine()
                ->warning('⚠ Source not found:')->space()->add($source, 'yellow')
                ->print();
            return 'failed';
        }

        if (file_exists($target)) {
            $relative = str_replace($projectRoot . '/', '', $target);
            $overwrite = $this->confirm("{$relative} already exists. Overwrite?", false);
            if (!$overwrite) {
                $this->cliLine()
                    ->muted('  ↷ Skipped')->space()->add($relative, 'gray')
                    ->print();
                return 'skipped';
            }
        }

        $dir = dirname($target);
        if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
            $this->cliLine()
                ->error('✗ Failed to create directory:')->space()->add($dir, 'red')
                ->print();
            return 'failed';
        }

        if (!copy($source, $target)) {
            $this->cliLine()
                ->error('✗ Failed to copy:')->space()->add($source, 'red')
                ->print();
            return 'failed';
        }

        $relative = str_replace($projectRoot . '/', '', $target);
        $this->cliLine()
            ->success('✓ Published')->space()->add($relative, 'cyan')
            ->print();

        return 'published';
    }

    private function generateMigration(string $projectRoot): ?string
    {
        $migrationsDir = "{$projectRoot}/database/migrations";
        if (!is_dir($migrationsDir) && !mkdir($migrationsDir, 0755, true) && !is_dir($migrationsDir)) {
            return null;
        }

        $timestamp = date('Y_m_d_His');
        $filename = "{$migrationsDir}/{$timestamp}_create_permissions_tables.php";

        $content = $this->migrationStub();
        if (file_put_contents($filename, $content) === false) {
            return null;
        }

        return $filename;
    }

    private function migrationStub(): string
    {
        return <<<'PHP'
<?php
declare(strict_types=1);

/**
 * MonkeysLegion Permissions — Database Migration
 *
 * Creates the core RBAC tables for the permissions system.
 * Auto-generated by permissions:install
 */
return new class {
    public function up(\PDO $pdo): void
    {
        $pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS perm_roles (
                id          INTEGER PRIMARY KEY AUTO_INCREMENT,
                `key`       VARCHAR(64)  NOT NULL UNIQUE,
                name        VARCHAR(128) NOT NULL,
                description TEXT         DEFAULT NULL,
                `level`     INT          NOT NULL DEFAULT 0,
                metadata    JSON         DEFAULT NULL,
                created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_roles_key (`key`),
                INDEX idx_roles_level (`level`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        SQL);

        $pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS perm_permissions (
                id          INTEGER PRIMARY KEY AUTO_INCREMENT,
                `key`       VARCHAR(128) NOT NULL UNIQUE,
                name        VARCHAR(128) NOT NULL,
                description TEXT         DEFAULT NULL,
                `group`     VARCHAR(64)  DEFAULT NULL,
                created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_permissions_key (`key`),
                INDEX idx_permissions_group (`group`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        SQL);

        $pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS perm_user_roles (
                id         INTEGER PRIMARY KEY AUTO_INCREMENT,
                user_id    VARCHAR(64) NOT NULL,
                role_id    INTEGER     NOT NULL,
                granted_by VARCHAR(64) DEFAULT NULL,
                granted_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP   NULL DEFAULT NULL,
                UNIQUE KEY uk_user_role (user_id, role_id),
                INDEX idx_user_roles_user (user_id),
                FOREIGN KEY (role_id) REFERENCES perm_roles(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        SQL);

        $pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS perm_user_permissions (
                id            INTEGER PRIMARY KEY AUTO_INCREMENT,
                user_id       VARCHAR(64) NOT NULL,
                permission_id INTEGER     NOT NULL,
                granted_by    VARCHAR(64) DEFAULT NULL,
                granted_at    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at    TIMESTAMP   NULL DEFAULT NULL,
                UNIQUE KEY uk_user_perm (user_id, permission_id),
                INDEX idx_user_perms_user (user_id),
                FOREIGN KEY (permission_id) REFERENCES perm_permissions(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        SQL);

        $pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS perm_stored_rules (
                id           INTEGER PRIMARY KEY AUTO_INCREMENT,
                name         VARCHAR(128)  NOT NULL,
                `key`        VARCHAR(128)  NOT NULL UNIQUE,
                predicate    TEXT          NOT NULL,
                priority     INT           NOT NULL DEFAULT 0,
                is_active    TINYINT(1)    NOT NULL DEFAULT 1,
                metadata     JSON          DEFAULT NULL,
                created_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_rules_key (`key`),
                INDEX idx_rules_active_priority (is_active, priority)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        SQL);

        $pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS perm_permission_requests (
                id                INTEGER PRIMARY KEY AUTO_INCREMENT,
                user_id           VARCHAR(64)  NOT NULL,
                type              VARCHAR(32)  NOT NULL DEFAULT 'permission',
                target_key        VARCHAR(128) NOT NULL,
                reason            TEXT         DEFAULT NULL,
                status            VARCHAR(32)  NOT NULL DEFAULT 'pending',
                reviewed_by       VARCHAR(64)  DEFAULT NULL,
                review_note       TEXT         DEFAULT NULL,
                requested_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                reviewed_at       TIMESTAMP    NULL DEFAULT NULL,
                expires_at        TIMESTAMP    NULL DEFAULT NULL,
                INDEX idx_requests_user (user_id),
                INDEX idx_requests_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        SQL);
    }

    public function down(\PDO $pdo): void
    {
        $pdo->exec('DROP TABLE IF EXISTS perm_permission_requests');
        $pdo->exec('DROP TABLE IF EXISTS perm_stored_rules');
        $pdo->exec('DROP TABLE IF EXISTS perm_user_permissions');
        $pdo->exec('DROP TABLE IF EXISTS perm_user_roles');
        $pdo->exec('DROP TABLE IF EXISTS perm_permissions');
        $pdo->exec('DROP TABLE IF EXISTS perm_roles');
    }
};

PHP;
    }

    private function countResult(string $result, int &$published, int &$skipped, int &$failed): void
    {
        match ($result) {
            'published' => $published++,
            'skipped'   => $skipped++,
            default     => $failed++,
        };
    }

    private function resolveProjectRoot(): string
    {
        // Try base_path() helper, fall back to working directory
        if (function_exists('base_path')) {
            return base_path();
        }

        return getcwd() ?: dirname(__DIR__, 5);
    }

    private function showHeader(): void
    {
        $this->cliLine()->newline()->print();
        $this->cliLine()
            ->add('MonkeysLegion Permissions Installer', 'cyan', 'bold')
            ->print();
        $this->cliLine()
            ->muted('Publish entities, config, and migration stubs to your application')
            ->newline()
            ->print();
    }

    private function showSummary(int $published, int $skipped, int $failed): void
    {
        $this->cliLine()
            ->success('✓ Permissions installation complete!')
            ->print();

        $this->cliLine()->info('Summary:')->print();
        $this->cliLine()
            ->add('  • Published: ', 'white')->add((string) $published, 'green', 'bold')
            ->print();
        $this->cliLine()
            ->add('  • Skipped:   ', 'white')->add((string) $skipped, 'yellow', 'bold')
            ->print();
        $this->cliLine()
            ->add('  • Failed:    ', 'white')->add((string) $failed, $failed > 0 ? 'red' : 'green', 'bold')
            ->print();

        $this->cliLine()->newline()->print();
        $this->cliLine()
            ->muted('Next steps:')
            ->print();
        $this->cliLine()
            ->add('  1. ', 'white')->muted('Run ')->add('php ml migrate', 'cyan')->muted(' to create the tables')
            ->print();
        $this->cliLine()
            ->add('  2. ', 'white')->muted('Edit ')->add('config/permissions.mlc', 'cyan')->muted(' to customize settings')
            ->print();
        $this->cliLine()
            ->add('  3. ', 'white')->muted('Register ')->add('PermissionsProvider', 'cyan')->muted(' in your app providers')
            ->print();
    }
}
