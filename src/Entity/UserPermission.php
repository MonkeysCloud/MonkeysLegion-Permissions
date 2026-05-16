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
 * Represents a direct grant of a permission to a user.
 */
#[Entity(table: 'perm_user_permissions')]
#[Index(columns: ['user_id', 'tenant_id'], name: 'idx_perm_user_permissions_user_tenant')]
class UserPermission
{
    #[Id]
    #[Field(type: 'unsignedBigInt', autoIncrement: true)]
    public private(set) int $id;

    #[Field(type: 'string', length: 36)]
    #[Fillable]
    public string $user_id;

    #[Field(type: 'unsignedBigInt')]
    #[Fillable]
    public int $permission_id;

    #[Field(type: 'string', length: 36, nullable: true)]
    #[Fillable]
    public ?string $tenant_id = null;

    #[Field(type: 'string', length: 36, nullable: true)]
    #[Fillable]
    public ?string $granted_by = null;

    #[Field(type: 'datetime')]
    public private(set) \DateTimeImmutable $granted_at;

    // ── Relationships ──────────────────────────────────────────

    #[ManyToOne(targetEntity: Permission::class)]
    public Permission $permission;

    public function __construct()
    {
        $this->granted_at = new \DateTimeImmutable();
    }
}
