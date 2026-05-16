<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Entity;

use MonkeysLegion\Entity\Attributes\Entity;
use MonkeysLegion\Entity\Attributes\Field;
use MonkeysLegion\Entity\Attributes\Id;
use MonkeysLegion\Entity\Attributes\Fillable;
use MonkeysLegion\Entity\Attributes\Timestamps;
use MonkeysLegion\Entity\Attributes\ManyToMany;
use MonkeysLegion\Entity\Attributes\ManyToOne;
use MonkeysLegion\Entity\Attributes\OneToMany;
use MonkeysLegion\Entity\Attributes\JoinTable;
use MonkeysLegion\Entity\Attributes\Index;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Represents a functional Role in the RBAC system.
 */
#[Entity(table: 'perm_roles')]
#[Timestamps]
#[Index(columns: ['name', 'tenant_id'], name: 'idx_perm_roles_name_tenant')]
class Role
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

    #[Field(type: 'unsignedBigInt', nullable: true)]
    #[Fillable]
    public ?int $parent_id = null;

    #[Field(type: 'string', length: 36, nullable: true)]
    #[Fillable]
    public ?string $tenant_id = null;

    #[Field(type: 'datetime')]
    public private(set) \DateTimeImmutable $created_at;

    #[Field(type: 'datetime')]
    public private(set) \DateTimeImmutable $updated_at;

    // ── Relationships ──────────────────────────────────────────

    #[ManyToOne(targetEntity: self::class, inversedBy: 'children')]
    public ?self $parent = null;

    /** @var list<Role> */
    #[OneToMany(targetEntity: self::class, mappedBy: 'parent')]
    public array $children = [];

    /** @var list<Permission> */
    #[ManyToMany(targetEntity: Permission::class, inversedBy: 'roles')]
    #[JoinTable(name: 'perm_role_permissions', joinColumn: 'role_id', inverseColumn: 'permission_id')]
    public array $permissions = [];
}
