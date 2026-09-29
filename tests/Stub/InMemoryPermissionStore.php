<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Stub;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Permissions\Store\PermissionStoreInterface;

/**
 * In-memory implementation of PermissionStoreInterface for test isolation.
 */
final class InMemoryPermissionStore implements PermissionStoreInterface
{
    /** @var array<int|string, list<string>> user_id => roles */
    private array $roles = [];

    /** @var array<int|string, list<string>> user_id => permissions */
    private array $permissions = [];

    /**
     * @param int|string $userId
     * @param list<string> $roles
     */
    public function setRoles(int|string $userId, array $roles): void
    {
        $this->roles[$userId] = $roles;
    }

    /**
     * @param int|string $userId
     * @param list<string> $permissions
     */
    public function setPermissions(int|string $userId, array $permissions): void
    {
        $this->permissions[$userId] = $permissions;
    }

    public function addRole(int|string $userId, string $role): void
    {
        $this->roles[$userId] ??= [];
        if (!in_array($role, $this->roles[$userId], true)) {
            $this->roles[$userId][] = $role;
        }
    }

    public function addPermission(int|string $userId, string $permission): void
    {
        $this->permissions[$userId] ??= [];
        if (!in_array($permission, $this->permissions[$userId], true)) {
            $this->permissions[$userId][] = $permission;
        }
    }

    public function clear(): void
    {
        $this->roles = [];
        $this->permissions = [];
    }

    public function hasRole(AuthenticatableInterface $identity, string $role, int|string|null $tenant = null): bool
    {
        $id = $identity->getAuthIdentifier();
        return isset($this->roles[$id]) && in_array($role, $this->roles[$id], true);
    }

    public function hasPermission(AuthenticatableInterface $identity, string $permission, int|string|null $tenant = null): bool
    {
        $id = $identity->getAuthIdentifier();
        return isset($this->permissions[$id]) && in_array($permission, $this->permissions[$id], true);
    }
}
