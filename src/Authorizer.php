<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Permissions\Contracts\AuthorizerInterface;
use MonkeysLegion\Permissions\Policy\PolicyResolver;
use MonkeysLegion\Permissions\Exceptions\AuthorizationException;
use MonkeysLegion\Permissions\Store\PermissionStoreInterface;
use MonkeysLegion\Permissions\Cache\CacheLayer;
use MonkeysLegion\Permissions\Rule\RuleEngine;
use MonkeysLegion\Permissions\Event\AuthorizationChecked;
use MonkeysLegion\Permissions\Event\AuthorizationDenied;
use MonkeysLegion\Permissions\Event\PolicyEvaluated;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Core engine for evaluating roles, permissions, policies, and gates.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class Authorizer implements AuthorizerInterface
{
    public function __construct(
        private readonly Gate $gate,
        private readonly PolicyResolver $policies,
        private readonly PermissionStoreInterface $store,
        private readonly CacheLayer $cache,
        private readonly ?RuleEngine $ruleEngine = null,
        private readonly ?EventDispatcherInterface $events = null,
    ) {}

    public function authorize(AuthenticatableInterface $identity, string $ability, mixed $resource = null, int|string|null $tenant = null): bool
    {
        $decision = $this->inspect($identity, $ability, $resource, $tenant);

        if ($decision->isDenied() || $decision->isAbstain()) {
            throw new AuthorizationException($decision->reason ?? "This action is unauthorized.", $decision);
        }

        return true;
    }

    public function inspect(AuthenticatableInterface $identity, string $ability, mixed $resource = null, int|string|null $tenant = null): Decision
    {
        $cacheKey = "inspect_{$identity->getAuthIdentifier()}_{$ability}_" . 
            (is_object($resource) ? spl_object_hash($resource) : (is_string($resource) ? $resource : '')) . "_{$tenant}";

        /** @var Decision $result */
        $result = $this->cache->get($cacheKey, function () use ($identity, $ability, $resource, $tenant) {
            return $this->resolveDecision($identity, $ability, $resource, $tenant);
        });

        // Dispatch audit events
        $resourceClass = $resource !== null
            ? (is_object($resource) ? get_class($resource) : (is_string($resource) ? $resource : null))
            : null;
        $userId = (string) $identity->getAuthIdentifier();

        $this->events?->dispatch(new AuthorizationChecked(
            userId: $userId,
            ability: $ability,
            resourceClass: $resourceClass,
            decision: $result,
            tenantId: $tenant,
        ));

        if ($result->isDenied()) {
            $this->events?->dispatch(new AuthorizationDenied(
                userId: $userId,
                ability: $ability,
                resourceClass: $resourceClass,
                decision: $result,
                tenantId: $tenant,
            ));
        }

        return $result;
    }

    private function resolveDecision(AuthenticatableInterface $identity, string $ability, mixed $resource = null, int|string|null $tenant = null): Decision
    {
        // 1. Check if there's a specific Policy for this resource.
        if ($resource !== null) {
            $policy = $this->policies->resolve($resource);
            if ($policy !== null) {
                // Check 'before' hook
                $before = $policy->before($identity, $ability, $resource);
                if ($before !== null) {
                    return $before;
                }

                if (method_exists($policy, $ability)) {
                    /** @var Decision $result */
                    $result = $policy->{$ability}($identity, $resource);

                    $this->events?->dispatch(new PolicyEvaluated(
                        userId: (string) $identity->getAuthIdentifier(),
                        policyClass: get_class($policy),
                        ability: $ability,
                        decision: $result,
                    ));

                    return $result;
                }
            }
        }

        // 2. Check Gate if no policy was found or resource is null.
        if ($this->gate->has($ability)) {
            return $this->gate->inspect($ability, $identity, $resource);
        }

        // 3. Evaluate database-stored ABAC rules.
        if ($this->ruleEngine !== null) {
            $ruleResult = $this->ruleEngine->evaluate($identity, $ability, $resource, $tenant);
            if ($ruleResult->isDenied) {
                return Decision::deny($ruleResult->reason);
            }
            if ($ruleResult->isAllowed) {
                return Decision::allow();
            }
            // Abstain — continue to RBAC fallback.
        }

        // 4. Fallback to RBAC permission check.
        if ($this->hasPermission($identity, $ability, $tenant)) {
            return Decision::allow();
        }

        return Decision::deny();
    }

    public function hasRole(AuthenticatableInterface $identity, string $role, int|string|null $tenant = null): bool
    {
        $cacheKey = "role_{$identity->getAuthIdentifier()}_{$role}_{$tenant}";
        return (bool) $this->cache->get($cacheKey, fn() => $this->store->hasRole($identity, $role, $tenant));
    }

    public function hasPermission(AuthenticatableInterface $identity, string $permission, int|string|null $tenant = null): bool
    {
        $cacheKey = "perm_{$identity->getAuthIdentifier()}_{$permission}_{$tenant}";
        return (bool) $this->cache->get($cacheKey, fn() => $this->store->hasPermission($identity, $permission, $tenant));
    }
}
