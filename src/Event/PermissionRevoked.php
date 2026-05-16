<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Event;

use MonkeysLegion\Events\Event;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Dispatched when a permission is revoked from a user or role.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class PermissionRevoked extends Event
{
    public function __construct(
        public readonly string $permission,
        public readonly string $granteeId,
        public readonly string $granteeType,
        public readonly ?string $revokedBy = null,
        public readonly int|string|null $tenantId = null,
    ) {
        parent::__construct();
    }
}
