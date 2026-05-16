<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Attributes;

use Attribute;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Requires the identity to have the specified permission(s) to access the target.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
class RequiresPermission
{
    /**
     * @param string|null        $permission Primary permission required.
     * @param list<string>       $allOf      Require ALL of these permissions.
     * @param list<string>       $anyOf      Require ANY of these permissions.
     * @param string|null        $tenant     Optional tenant ID for scoped access.
     */
    public function __construct(
        public readonly ?string $permission = null,
        public readonly array $allOf = [],
        public readonly array $anyOf = [],
        public readonly ?string $tenant = null,
    ) {
        if ($permission === null && empty($allOf) && empty($anyOf)) {
            throw new \InvalidArgumentException('RequiresPermission must specify at least one permission.');
        }
    }
}
