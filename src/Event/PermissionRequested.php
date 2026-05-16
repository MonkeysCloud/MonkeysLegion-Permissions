<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Event;

use MonkeysLegion\Events\Event;
use MonkeysLegion\Permissions\Entity\RequestType;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Dispatched when a user submits a permission or role request.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class PermissionRequested extends Event
{
    public function __construct(
        public readonly int $requestId,
        public readonly string $requesterId,
        public readonly RequestType $type,
        public readonly string $target,
        public readonly ?string $reason = null,
        public readonly int|string|null $tenantId = null,
    ) {
        parent::__construct();
    }
}
