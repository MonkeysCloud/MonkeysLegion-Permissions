<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Event;

use MonkeysLegion\Events\Event;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Dispatched when a role is removed from a user.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class RoleRevoked extends Event
{
    public function __construct(
        public readonly string $role,
        public readonly string $userId,
        public readonly ?string $revokedBy = null,
        public readonly int|string|null $tenantId = null,
    ) {
        parent::__construct();
    }
}
