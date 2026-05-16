<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Store;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Interface for querying roles and permissions from storage.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
interface PermissionStoreInterface
{
    /**
     * Determine if the user has a specific role.
     */
    public function hasRole(AuthenticatableInterface $identity, string $role, int|string|null $tenant = null): bool;

    /**
     * Determine if the user has a specific permission.
     */
    public function hasPermission(AuthenticatableInterface $identity, string $permission, int|string|null $tenant = null): bool;
}
