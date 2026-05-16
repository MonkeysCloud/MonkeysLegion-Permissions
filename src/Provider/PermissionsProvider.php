<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Provider;

use MonkeysLegion\DI\Contracts\ServiceProviderInterface;
use MonkeysLegion\DI\ContainerBuilder;
use MonkeysLegion\Permissions\Authorizer;
use MonkeysLegion\Permissions\AuthorizationManager;
use MonkeysLegion\Permissions\Gate;
use MonkeysLegion\Permissions\Policy\PolicyResolver;
use MonkeysLegion\Permissions\Contracts\AuthorizerInterface;
use MonkeysLegion\Permissions\Cache\CacheLayer;
use MonkeysLegion\Permissions\Store\PermissionStoreInterface;
use MonkeysLegion\Permissions\Store\DatabaseStore;
use MonkeysLegion\Permissions\Middleware\AuthorizationMiddleware;
use MonkeysLegion\Permissions\Rule\RuleEngine;
use MonkeysLegion\Permissions\Rule\RuleRepository;
use MonkeysLegion\Permissions\Workflow\RequestManager;
use MonkeysLegion\Permissions\Sync\RoleSyncManager;
use MonkeysLegion\Permissions\Apex\ApexPolicyAdapter;
use MonkeysLegion\Permissions\Apex\ApexGateRegistrar;
use MonkeysLegion\Database\Contracts\ConnectionManagerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Container\ContainerInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Registers the authorization services in the DI container.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class PermissionsProvider implements ServiceProviderInterface
{
    public function register(ContainerBuilder $builder): void
    {
        $builder->set(Gate::class, fn() => new Gate());
        
        $builder->set(PolicyResolver::class, function(ContainerInterface $c) {
            $policyMap = $c->has('config.permissions.policies') ? $c->get('config.permissions.policies') : [];
            assert(is_array($policyMap));
            /** @var array<string, class-string<\MonkeysLegion\Permissions\Policy\Policy>> $policyMap */
            return new PolicyResolver($c, $policyMap);
        });

        $builder->set(CacheLayer::class, function(ContainerInterface $c) {
            // Resolve PSR-16 cache if available
            $psrCache = $c->has(\Psr\SimpleCache\CacheInterface::class) ? $c->get(\Psr\SimpleCache\CacheInterface::class) : null;
            assert($psrCache === null || $psrCache instanceof \Psr\SimpleCache\CacheInterface);
            return new CacheLayer($psrCache);
        });

        $builder->set(PermissionStoreInterface::class, function(ContainerInterface $c) {
            $db = $c->get(ConnectionManagerInterface::class);
            assert($db instanceof ConnectionManagerInterface);
            return new DatabaseStore($db);
        });

        // ── Rule Engine (v1.1 — composable ABAC rules) ─────────

        $builder->set(RuleEngine::class, function(ContainerInterface $c) {
            $db = $c->get(ConnectionManagerInterface::class);
            assert($db instanceof ConnectionManagerInterface);
            $cache = $c->get(CacheLayer::class);
            assert($cache instanceof CacheLayer);
            return new RuleEngine($db, $cache);
        });

        $builder->set(RuleRepository::class, function(ContainerInterface $c) {
            $db = $c->get(ConnectionManagerInterface::class);
            assert($db instanceof ConnectionManagerInterface);
            return new RuleRepository($db);
        });

        // ── Authorizer ─────────────────────────────────────────

        $builder->set(AuthorizerInterface::class, function(ContainerInterface $c) {
            $gate = $c->get(Gate::class);
            assert($gate instanceof Gate);
            $policies = $c->get(PolicyResolver::class);
            assert($policies instanceof PolicyResolver);
            $store = $c->get(PermissionStoreInterface::class);
            assert($store instanceof PermissionStoreInterface);
            $cache = $c->get(CacheLayer::class);
            assert($cache instanceof CacheLayer);
            $ruleEngine = $c->get(RuleEngine::class);
            assert($ruleEngine instanceof RuleEngine);

            $events = $c->has(EventDispatcherInterface::class) ? $c->get(EventDispatcherInterface::class) : null;
            assert($events === null || $events instanceof EventDispatcherInterface);

            return new Authorizer(
                $gate,
                $policies,
                $store,
                $cache,
                $ruleEngine,
                $events,
            );
        });

        // ── Workflow (v1.2 — request-to-grant approvals) ──────

        $builder->set(RequestManager::class, function(ContainerInterface $c) {
            $db = $c->get(ConnectionManagerInterface::class);
            assert($db instanceof ConnectionManagerInterface);

            $events = $c->has(EventDispatcherInterface::class) ? $c->get(EventDispatcherInterface::class) : null;
            assert($events === null || $events instanceof EventDispatcherInterface);

            return new RequestManager($db, $events);
        });

        // ── Sync (v1.3 — LDAP/SAML role-sync adapters) ──────

        $builder->set(RoleSyncManager::class, function(ContainerInterface $c) {
            $db = $c->get(ConnectionManagerInterface::class);
            assert($db instanceof ConnectionManagerInterface);

            $events = $c->has(EventDispatcherInterface::class) ? $c->get(EventDispatcherInterface::class) : null;
            assert($events === null || $events instanceof EventDispatcherInterface);

            $logger = $c->has(\Psr\Log\LoggerInterface::class) ? $c->get(\Psr\Log\LoggerInterface::class) : null;
            assert($logger === null || $logger instanceof \Psr\Log\LoggerInterface);

            return new RoleSyncManager($db, events: $events, logger: $logger);
        });

        $builder->set(AuthorizationManager::class, function(ContainerInterface $c) {
            $authorizer = $c->get(AuthorizerInterface::class);
            assert($authorizer instanceof AuthorizerInterface);
            $gate = $c->get(Gate::class);
            assert($gate instanceof Gate);

            return new AuthorizationManager(
                $authorizer,
                $gate
            );
        });

        $builder->set(AuthorizationMiddleware::class, function(ContainerInterface $c) {
            $authorizer = $c->get(AuthorizerInterface::class);
            assert($authorizer instanceof AuthorizerInterface);
            return new AuthorizationMiddleware($authorizer);
        });

        // ── Apex AI (v2.0 — LLM-backed fuzzy policies) ──────

        $builder->set(ApexPolicyAdapter::class, function(ContainerInterface $c) {
            // Only available when monkeyslegion-apex is installed
            if (!$c->has(\MonkeysLegion\Apex\AI::class)) {
                throw new \RuntimeException(
                    'ApexPolicyAdapter requires monkeyslegion-apex. Install via: composer require monkeyscloud/monkeyslegion-apex'
                );
            }

            $ai = $c->get(\MonkeysLegion\Apex\AI::class);
            assert($ai instanceof \MonkeysLegion\Apex\AI);
            $cache = $c->get(CacheLayer::class);
            assert($cache instanceof CacheLayer);

            return new ApexPolicyAdapter($ai, $cache);
        });

        $builder->set(ApexGateRegistrar::class, function(ContainerInterface $c) {
            $adapter = $c->get(ApexPolicyAdapter::class);
            assert($adapter instanceof ApexPolicyAdapter);
            $gate = $c->get(Gate::class);
            assert($gate instanceof Gate);

            $events = $c->has(EventDispatcherInterface::class) ? $c->get(EventDispatcherInterface::class) : null;
            assert($events === null || $events instanceof EventDispatcherInterface);

            return new ApexGateRegistrar($adapter, $gate, $events);
        });
    }
}
