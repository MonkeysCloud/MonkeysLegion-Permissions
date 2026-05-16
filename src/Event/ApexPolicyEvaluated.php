<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Event;

use MonkeysLegion\Events\Event;
use MonkeysLegion\Permissions\Apex\ApexDecision;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Dispatched after an Apex AI policy evaluation completes.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class ApexPolicyEvaluated extends Event
{
    public function __construct(
        public readonly string $policyPrompt,
        public readonly string $userId,
        public readonly ApexDecision $decision,
    ) {
        parent::__construct();
    }
}
