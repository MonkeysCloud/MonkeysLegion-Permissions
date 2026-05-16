<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Sync;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Value object representing the result of a role sync operation.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class SyncResult
{
    /**
     * @param list<string> $added     Roles that were assigned during sync.
     * @param list<string> $removed   Roles that were revoked during sync.
     * @param list<string> $unchanged Roles that remained untouched.
     * @param list<string> $skipped   External roles skipped (no local match).
     * @param list<string> $errors    Error messages encountered during sync.
     */
    public function __construct(
        public readonly string $userId,
        public readonly string $providerName,
        public readonly SyncStrategy $strategy,
        public readonly array $added = [],
        public readonly array $removed = [],
        public readonly array $unchanged = [],
        public readonly array $skipped = [],
        public readonly array $errors = [],
    ) {}

    // ── Computed Properties ─────────────────────────────────────

    public int $addedCount {
        get => count($this->added);
    }

    public int $removedCount {
        get => count($this->removed);
    }

    public int $totalChanges {
        get => $this->addedCount + $this->removedCount;
    }

    public bool $hasErrors {
        get => $this->errors !== [];
    }

    public bool $hasChanges {
        get => $this->totalChanges > 0;
    }

    /**
     * Produce a human-readable summary line.
     */
    public function summary(): string
    {
        return sprintf(
            '[%s] User %s: +%d added, -%d removed, %d unchanged, %d skipped%s',
            $this->providerName,
            $this->userId,
            $this->addedCount,
            $this->removedCount,
            count($this->unchanged),
            count($this->skipped),
            $this->hasErrors ? ', ' . count($this->errors) . ' error(s)' : '',
        );
    }
}
