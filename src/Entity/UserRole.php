<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Entity;

use MonkeysLegion\Entity\Attributes\Entity;
use MonkeysLegion\Entity\Attributes\Field;
use MonkeysLegion\Entity\Attributes\Id;
use MonkeysLegion\Entity\Attributes\Fillable;
use MonkeysLegion\Entity\Attributes\ManyToOne;
use MonkeysLegion\Entity\Attributes\Index;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Represents an assignment of a role to a user (pivot).
 */
#[Entity(table: 'perm_user_roles')]
#[Index(columns: ['user_id', 'tenant_id'], name: 'idx_perm_user_roles_user_tenant')]
class UserRole
{
    #[Id]
    #[Field(type: 'unsignedBigInt', autoIncrement: true)]
    public private(set) int $id;

    #[Field(type: 'string', length: 36)]
    #[Fillable]
    public string $user_id;

    #[Field(type: 'unsignedBigInt')]
    #[Fillable]
    public int $role_id;

    #[Field(type: 'string', length: 36, nullable: true)]
    #[Fillable]
    public ?string $tenant_id = null;

    #[Field(type: 'string', length: 36, nullable: true)]
    #[Fillable]
    public ?string $granted_by = null;

    #[Field(type: 'datetime')]
    public private(set) \DateTimeImmutable $granted_at;

    // ── Relationships ──────────────────────────────────────────

    #[ManyToOne(targetEntity: Role::class)]
    public Role $role;

    public function __construct()
    {
        $this->granted_at = new \DateTimeImmutable();
    }
}
