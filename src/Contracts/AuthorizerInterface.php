<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Contracts;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Permissions\Decision;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Contract for the core authorization decision engine.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
interface AuthorizerInterface
{
    /**
     * Determine if the given identity has the requested permission or role.
     * Throws an exception if the action is denied.
     *
     * @param AuthenticatableInterface $identity The user or system making the request
     * @param string            $ability  The permission or action name
     * @param mixed             $resource Optional resource (entity) being acted upon
     * @param int|string|null   $tenant   Optional tenant scope
     *
     * @return true Returns true if allowed
     *
     * @throws \MonkeysLegion\Permissions\Exceptions\AuthorizationException If denied
     */
    public function authorize(AuthenticatableInterface $identity, string $ability, mixed $resource = null, int|string|null $tenant = null): bool;

    /**
     * Check if the given identity can perform the action.
     * Returns a Decision object instead of throwing.
     *
     * @param AuthenticatableInterface $identity
     * @param string            $ability
     * @param mixed             $resource
     * @param int|string|null   $tenant
     *
     * @return Decision The evaluated decision (allow/deny/abstain)
     */
    public function inspect(AuthenticatableInterface $identity, string $ability, mixed $resource = null, int|string|null $tenant = null): Decision;

    /**
     * Check if the identity has a specific role.
     *
     * @param AuthenticatableInterface $identity
     * @param string            $role
     * @param int|string|null   $tenant
     *
     * @return bool
     */
    public function hasRole(AuthenticatableInterface $identity, string $role, int|string|null $tenant = null): bool;

    /**
     * Check if the identity has a specific permission via RBAC.
     * 
     * @param AuthenticatableInterface $identity
     * @param string            $permission
     * @param int|string|null   $tenant
     *
     * @return bool
     */
    public function hasPermission(AuthenticatableInterface $identity, string $permission, int|string|null $tenant = null): bool;
}
