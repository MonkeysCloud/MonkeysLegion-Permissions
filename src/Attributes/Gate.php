<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Attributes;

use Attribute;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Requires the identity to pass a specific named gate to access the target.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
class Gate
{
    /**
     * @param string $name The name of the registered gate.
     */
    public function __construct(
        public readonly string $name,
    ) {}
}
