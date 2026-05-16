<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Entity;

use MonkeysLegion\Entity\Attributes\Entity;
use MonkeysLegion\Entity\Attributes\Id;
use MonkeysLegion\Entity\Attributes\Field;
use MonkeysLegion\Entity\Attributes\Timestamps;
use MonkeysLegion\Entity\Attributes\Index;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Persisted ABAC rule stored as a JSON predicate tree.
 * Enables admin-UI editing and runtime-configurable policies.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
#[Entity(table: 'perm_rules')]
#[Timestamps]
#[Index(columns: ['name'], unique: true)]
#[Index(columns: ['entity_class', 'ability'])]
#[Index(columns: ['is_active'])]
final class StoredRule
{
    // ── Fields ──────────────────────────────────────────────────

    #[Id]
    #[Field(type: 'integer')]
    public private(set) int $id;

    #[Field(type: 'string', length: 128)]
    public string $name {
        set(string $value) {
            if (trim($value) === '') {
                throw new \InvalidArgumentException('Rule name cannot be empty.');
            }
            $this->name = trim($value);
        }
    }

    #[Field(type: 'string', length: 255, nullable: true)]
    public ?string $description = null;

    #[Field(type: 'string', length: 255, nullable: true)]
    public ?string $entity_class = null;

    #[Field(type: 'string', length: 128, nullable: true)]
    public ?string $ability = null;

    #[Field(type: 'text')]
    public string $predicate_json {
        set(string $value) {
            // Validate JSON on write
            json_decode($value, true, 512, JSON_THROW_ON_ERROR);
            $this->predicate_json = $value;
        }
    }

    #[Field(type: 'boolean')]
    public bool $is_active = true;

    #[Field(type: 'integer')]
    public int $priority = 0;

    #[Field(type: 'string', length: 64, nullable: true)]
    public ?string $guard = null;

    #[Field(type: 'integer', nullable: true)]
    public ?int $tenant_id = null;

    #[Field(type: 'datetime', nullable: true)]
    public ?\DateTimeImmutable $expires_at = null;

    // ── Computed Properties ─────────────────────────────────────

    public bool $isExpired {
        get => $this->expires_at !== null && $this->expires_at < new \DateTimeImmutable();
    }

    public bool $isEffective {
        get => $this->is_active && !$this->isExpired;
    }
}
