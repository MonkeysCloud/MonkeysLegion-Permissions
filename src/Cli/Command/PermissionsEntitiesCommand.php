<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Cli\Command;

use MonkeysLegion\Cli\Console\Attributes\Command as CommandAttr;
use MonkeysLegion\Cli\Console\Command;
use MonkeysLegion\Cli\Console\Traits\Cli;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Copies permissions entity stubs into the application's app/Entity/ directory.
 * Lightweight alternative to permissions:install when config/migrations are
 * already in place.
 *
 * Usage: php ml permissions:entities
 *        php ml permissions:entities --force   (overwrite existing)
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
#[CommandAttr('permissions:entities', 'Copy Permissions entity stubs into app/Entity/')]
final class PermissionsEntitiesCommand extends Command
{
    use Cli;

    /** @var list<string> */
    private const array ENTITIES = [
        'Permission.php',
        'Role.php',
        'UserRole.php',
        'UserPermission.php',
        'StoredRule.php',
        'PermissionRequest.php',
        'RequestStatus.php',
        'RequestType.php',
    ];

    protected function handle(): int
    {
        $projectRoot = $this->resolveProjectRoot();
        $sourceDir = dirname(__DIR__, 3) . '/src/Entity';
        $targetDir = "{$projectRoot}/app/Entity";
        $force = $this->hasOption('force');
        $published = 0;
        $skipped = 0;

        $this->cliLine()->newline()->print();
        $this->cliLine()
            ->add('Permissions — Entity Publisher', 'cyan', 'bold')
            ->print();
        $this->cliLine()
            ->muted('Copying entity stubs to app/Entity/')
            ->newline()
            ->print();

        if (!is_dir($targetDir) && !mkdir($targetDir, 0755, true) && !is_dir($targetDir)) {
            $this->cliLine()
                ->error('✗ Cannot create directory:')->space()->add($targetDir, 'red')
                ->print();
            return self::FAILURE;
        }

        foreach (self::ENTITIES as $file) {
            $source = "{$sourceDir}/{$file}";
            $target = "{$targetDir}/{$file}";

            if (!file_exists($source)) {
                $this->cliLine()
                    ->warning("⚠ Source not found: {$file}")
                    ->print();
                continue;
            }

            if (file_exists($target) && !$force) {
                $overwrite = $this->confirm("{$file} already exists. Overwrite?", false);
                if (!$overwrite) {
                    $this->cliLine()
                        ->muted("  ↷ Skipped")->space()->add($file, 'gray')
                        ->print();
                    $skipped++;
                    continue;
                }
            }

            if (copy($source, $target)) {
                $published++;
                $this->cliLine()
                    ->success('✓')->space()->add("app/Entity/{$file}", 'cyan')
                    ->print();
            } else {
                $this->cliLine()
                    ->error("✗ Failed to copy {$file}")
                    ->print();
            }
        }

        $this->cliLine()->newline()->print();
        $this->cliLine()
            ->success("Done!")->space()
            ->add((string) $published, 'green', 'bold')->muted(' published, ')
            ->add((string) $skipped, 'yellow', 'bold')->muted(' skipped')
            ->print();

        return self::SUCCESS;
    }

    private function resolveProjectRoot(): string
    {
        if (function_exists('base_path')) {
            return base_path();
        }

        return getcwd() ?: dirname(__DIR__, 5);
    }
}
