<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Stub;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;

/**
 * Test stub implementing AuthenticatableInterface for permission tests.
 */
final class TestUser implements AuthenticatableInterface
{
    /** @param list<string> $roles */
    public function __construct(
        private readonly int|string $id = 1,
        private readonly string $password = '$2y$12$hash',
        private readonly array $roles = [],
        private readonly array $permissions = [],
        private readonly int $tokenVersion = 1,
        private ?string $rememberToken = null,
    ) {}

    public function getAuthIdentifier(): int|string
    {
        return $this->id;
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthPassword(): string
    {
        return $this->password;
    }

    public function getTokenVersion(): int
    {
        return $this->tokenVersion;
    }

    public function getRememberToken(): ?string
    {
        return $this->rememberToken;
    }

    public function setRememberToken(?string $token): void
    {
        $this->rememberToken = $token;
    }

    /** @return list<string> */
    public function getRoles(): array
    {
        return $this->roles;
    }

    /** @return list<string> */
    public function getPermissions(): array
    {
        return $this->permissions;
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }

    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->permissions, true);
    }
}
