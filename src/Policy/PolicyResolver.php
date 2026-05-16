<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Policy;

use Psr\Container\ContainerInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Resolves the appropriate policy instance for a given entity class or object.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final readonly class PolicyResolver
{
    /**
     * @param ContainerInterface $container  DI container to resolve policy instances.
     * @param array<string, class-string<Policy>> $policyMap Mapping of Entity class to Policy class.
     */
    public function __construct(
        private ContainerInterface $container,
        private array $policyMap = [],
    ) {}

    /**
     * Resolves the policy instance for the given resource.
     *
     * @param mixed $resource The entity instance or class name.
     *
     * @return Policy|null
     */
    public function resolve(mixed $resource): ?Policy
    {
        $class = is_object($resource) ? get_class($resource) : (is_string($resource) ? $resource : '');

        if (!isset($this->policyMap[$class])) {
            return null;
        }

        $policyClass = $this->policyMap[$class];

        /** @var Policy $policy */
        $policy = $this->container->get($policyClass);

        return $policy;
    }
}
