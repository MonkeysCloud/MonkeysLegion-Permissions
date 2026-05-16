<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Entity;

use MonkeysLegion\Entity\Attributes\Entity;
use MonkeysLegion\Entity\Attributes\Field;
use MonkeysLegion\Entity\Attributes\Id;
use MonkeysLegion\Entity\Attributes\Fillable;
use MonkeysLegion\Entity\Attributes\Timestamps;
use MonkeysLegion\Entity\Attributes\ManyToMany;
use MonkeysLegion\Entity\Attributes\Index;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Represents an individual Permission in the RBAC system.
 */
#[Entity(table: 'perm_permissions')]
#[Timestamps]
#[Index(columns: ['name', 'tenant_id'], name: 'idx_perm_permissions_name_tenant')]
class Permission
{
    #[Id]
    #[Field(type: 'unsignedBigInt', autoIncrement: true)]
    public private(set) int $id;

    #[Field(type: 'string', length: 150)]
    #[Fillable]
    public string $name {
        set(string $value) {
            $this->name = strtolower(trim($value));
        }
    }

    #[Field(type: 'string', length: 100)]
    #[Fillable]
    public string $guard = 'default';

    #[Field(type: 'string', length: 255, nullable: true)]
    #[Fillable]
    public ?string $description = null;

    #[Field(type: 'string', length: 36, nullable: true)]
    #[Fillable]
    public ?string $tenant_id = null;

    #[Field(type: 'datetime')]
    public private(set) \DateTimeImmutable $created_at;

    #[Field(type: 'datetime')]
    public private(set) \DateTimeImmutable $updated_at;

    // ── Relationships ──────────────────────────────────────────

    /** @var list<Role> */
    #[ManyToMany(targetEntity: Role::class, mappedBy: 'permissions')]
    public array $roles = [];
}
