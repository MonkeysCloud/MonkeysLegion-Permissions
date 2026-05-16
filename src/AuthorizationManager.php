<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Permissions\Contracts\AuthorizerInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Facade / Top-level Manager for Authorization.
 * Provides a clean API over the underlying Authorizer engine.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class AuthorizationManager
{
    public function __construct(
        private readonly AuthorizerInterface $authorizer,
        private readonly Gate $gate,
    ) {}

    public function can(AuthenticatableInterface $identity, string $ability, mixed $resource = null, int|string|null $tenant = null): bool
    {
        return $this->authorizer->inspect($identity, $ability, $resource, $tenant)->isAllowed();
    }

    public function cannot(AuthenticatableInterface $identity, string $ability, mixed $resource = null, int|string|null $tenant = null): bool
    {
        return !$this->can($identity, $ability, $resource, $tenant);
    }

    public function authorize(AuthenticatableInterface $identity, string $ability, mixed $resource = null, int|string|null $tenant = null): void
    {
        $this->authorizer->authorize($identity, $ability, $resource, $tenant);
    }

    public function define(string $name, \Closure $callback): void
    {
        $this->gate->define($name, $callback);
    }
}
