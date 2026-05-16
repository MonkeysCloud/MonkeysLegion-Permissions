<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Event;

use MonkeysLegion\Events\Event;
use MonkeysLegion\Permissions\Decision;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Dispatched specifically when an authorization check results in denial.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class AuthorizationDenied extends Event
{
    public function __construct(
        public readonly string $userId,
        public readonly string $ability,
        public readonly ?string $resourceClass,
        public readonly Decision $decision,
        public readonly int|string|null $tenantId = null,
    ) {
        parent::__construct();
    }
}
