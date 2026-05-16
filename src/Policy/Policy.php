<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Policy;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Permissions\Decision;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Abstract base class for all Authorization Policies.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
abstract class Policy
{
    /**
     * Helper to return an explicit allow decision.
     */
    protected function allow(?string $reason = null): Decision
    {
        return Decision::allow($reason);
    }

    /**
     * Helper to return an explicit deny decision.
     */
    protected function deny(?string $reason = null): Decision
    {
        return Decision::deny($reason);
    }

    /**
     * Helper to abstain from making a decision.
     */
    protected function abstain(?string $reason = null): Decision
    {
        return Decision::abstain($reason);
    }

    /**
     * Hook that runs before any policy method.
     * If this returns a non-null Decision (e.g., for Super Admins), the specific method is skipped.
     */
    public function before(AuthenticatableInterface $identity, string $ability, mixed $resource = null): ?Decision
    {
        return null; // Default behavior is to proceed to the specific method.
    }
}
