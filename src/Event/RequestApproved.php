<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Event;

use MonkeysLegion\Events\Event;
use MonkeysLegion\Permissions\Entity\RequestType;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Dispatched when a permission/role request is approved.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class RequestApproved extends Event
{
    public function __construct(
        public readonly int $requestId,
        public readonly string $requesterId,
        public readonly string $reviewerId,
        public readonly RequestType $type,
        public readonly string $target,
        public readonly ?string $note = null,
        public readonly int|string|null $tenantId = null,
    ) {
        parent::__construct();
    }
}
