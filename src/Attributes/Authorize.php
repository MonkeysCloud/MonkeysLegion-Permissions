<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Attributes;

use Attribute;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Instructs the authorization middleware to evaluate a policy method.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
class Authorize
{
    /**
     * @param string      $ability   The policy method to call (e.g., 'update', 'delete').
     * @param string      $resource  The entity class name this policy applies to.
     * @param string|null $paramName The route parameter name containing the entity ID (for ABAC).
     */
    public function __construct(
        public readonly string $ability,
        public readonly string $resource,
        public readonly ?string $paramName = null,
    ) {}
}
