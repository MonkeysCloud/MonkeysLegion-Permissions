<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Permissions\Exceptions\AuthorizationException;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Registry for ad-hoc authorization closures (Gates).
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class Gate
{
    /** @var array<string, \Closure(AuthenticatableInterface, mixed...): (bool|Decision)> */
    private array $gates = [];

    /**
     * Define a new gate.
     *
     * @param string $name
     * @param \Closure(AuthenticatableInterface, mixed...): (bool|Decision) $callback
     */
    public function define(string $name, \Closure $callback): void
    {
        $this->gates[$name] = $callback;
    }

    /**
     * Determine if the given gate is defined.
     */
    public function has(string $name): bool
    {
        return isset($this->gates[$name]);
    }

    /**
     * Evaluate the gate.
     *
     * @param string $name
     * @param AuthenticatableInterface $identity
     * @param mixed ...$args
     *
     * @return Decision
     * @throws \InvalidArgumentException If the gate is not defined.
     */
    public function inspect(string $name, AuthenticatableInterface $identity, mixed ...$args): Decision
    {
        if (!$this->has($name)) {
            throw new \InvalidArgumentException("Gate [{$name}] is not defined.");
        }

        $result = $this->gates[$name]($identity, ...$args);

        if ($result instanceof Decision) {
            return $result;
        }

        return Decision::when((bool) $result);
    }

    /**
     * Evaluate the gate and throw if denied.
     *
     * @param string $name
     * @param AuthenticatableInterface $identity
     * @param mixed ...$args
     *
     * @return true
     * @throws AuthorizationException
     */
    public function authorize(string $name, AuthenticatableInterface $identity, mixed ...$args): bool
    {
        $decision = $this->inspect($name, $identity, ...$args);

        if ($decision->isDenied()) {
            throw new AuthorizationException($decision->reason ?? "This action is unauthorized by gate [{$name}].", $decision);
        }

        return true;
    }
}
