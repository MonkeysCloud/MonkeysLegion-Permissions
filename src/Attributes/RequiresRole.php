<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Attributes;

use Attribute;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Requires the identity to have the specified role(s) to access the target.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
class RequiresRole
{
    /**
     * @param string|null        $role   Primary role required.
     * @param list<string>       $allOf  Require ALL of these roles.
     * @param list<string>       $anyOf  Require ANY of these roles.
     * @param string|null        $tenant Optional tenant ID for scoped access.
     */
    public function __construct(
        public readonly ?string $role = null,
        public readonly array $allOf = [],
        public readonly array $anyOf = [],
        public readonly ?string $tenant = null,
    ) {
        if ($role === null && empty($allOf) && empty($anyOf)) {
            throw new \InvalidArgumentException('RequiresRole must specify at least one role.');
        }
    }
}
