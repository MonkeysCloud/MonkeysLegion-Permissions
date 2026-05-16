<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Event;

use MonkeysLegion\Events\Event;
use MonkeysLegion\Permissions\Decision;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Dispatched when a policy method is invoked during authorization.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class PolicyEvaluated extends Event
{
    public function __construct(
        public readonly string $userId,
        public readonly string $policyClass,
        public readonly string $ability,
        public readonly Decision $decision,
    ) {
        parent::__construct();
    }
}
