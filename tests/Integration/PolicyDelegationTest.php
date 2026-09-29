<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Integration;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Permissions\Authorizer;
use MonkeysLegion\Permissions\Cache\CacheLayer;
use MonkeysLegion\Permissions\Decision;
use MonkeysLegion\Permissions\Gate;
use MonkeysLegion\Permissions\Policy\Policy;
use MonkeysLegion\Permissions\Policy\PolicyResolver;
use MonkeysLegion\Permissions\Tests\Stub\InMemoryPermissionStore;
use MonkeysLegion\Permissions\Tests\Stub\TestUser;
use MonkeysLegion\Permissions\Tests\TestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;

/**
 * Integration tests for policy delegation: before() → method → fallback.
 */
final class PolicyDelegationTest extends TestCase
{
    private InMemoryPermissionStore $store;
    private CacheLayer $cache;

    /** @var ContainerInterface&MockObject */
    private ContainerInterface $container;

    protected function setUp(): void
    {
        $this->store = new InMemoryPermissionStore();
        $this->cache = new CacheLayer();
        $this->container = $this->createMock(ContainerInterface::class);
    }

    private function makeAuthorizer(string $entityClass, Policy $policy): Authorizer
    {
        $this->container->method('get')->willReturn($policy);
        $resolver = new PolicyResolver($this->container, [$entityClass => $policy::class]);
        return new Authorizer(
            new Gate(),
            $resolver,
            $this->store,
            $this->cache,
        );
    }

    public function test_policy_before_allows_bypass_for_super_admin(): void
    {
        $policy = new class extends Policy {
            public function before(AuthenticatableInterface $identity, string $ability, mixed $resource = null): ?Decision
            {
                if ($identity->getAuthIdentifier() === 1) {
                    return Decision::allow('super admin bypass');
                }
                return null;
            }

            public function update(AuthenticatableInterface $user, mixed $resource): Decision
            {
                return Decision::deny();
            }
        };

        $authorizer = $this->makeAuthorizer('stdClass', $policy);

        $superAdmin = new TestUser(id: 1);
        $regular    = new TestUser(id: 2);
        $resource   = new \stdClass();

        self::assertTrue($authorizer->inspect($superAdmin, 'update', $resource)->isAllowed());
        self::assertTrue($authorizer->inspect($regular, 'update', $resource)->isDenied());
    }

    public function test_policy_method_called_when_before_returns_null(): void
    {
        $policy = new class extends Policy {
            public function before(AuthenticatableInterface $identity, string $ability, mixed $resource = null): ?Decision
            {
                return null;
            }

            public function view(AuthenticatableInterface $user, mixed $resource): Decision
            {
                return Decision::allow('policy allows view');
            }

            public function delete(AuthenticatableInterface $user, mixed $resource): Decision
            {
                return Decision::deny('policy denies delete');
            }
        };

        $authorizer = $this->makeAuthorizer('stdClass', $policy);
        $user = new TestUser();
        $resource = new \stdClass();

        self::assertTrue($authorizer->inspect($user, 'view', $resource)->isAllowed());
        self::assertTrue($authorizer->inspect($user, 'delete', $resource)->isDenied());
    }

    public function test_policy_abstain_does_not_fall_through_to_rbac(): void
    {
        // When a policy method returns abstain, the Authorizer returns it directly
        // (policy decisions are final, including abstain).
        $policy = new class extends Policy {
            public function before(AuthenticatableInterface $identity, string $ability, mixed $resource = null): ?Decision
            {
                return null;
            }

            public function edit(AuthenticatableInterface $user, mixed $resource): Decision
            {
                return Decision::abstain('no opinion');
            }
        };

        // RBAC has the permission, but policy abstain is returned directly.
        $this->store->setPermissions(1, ['edit']);

        $authorizer = $this->makeAuthorizer('stdClass', $policy);
        $user = new TestUser(id: 1);
        $resource = new \stdClass();

        $decision = $authorizer->inspect($user, 'edit', $resource);

        self::assertTrue($decision->isAbstain());
        self::assertSame('no opinion', $decision->reason);
    }

    public function test_policy_abstain_is_returned_as_abstain(): void
    {
        // Policy abstain is returned as-is (not converted to deny).
        $policy = new class extends Policy {
            public function before(AuthenticatableInterface $identity, string $ability, mixed $resource = null): ?Decision
            {
                return null;
            }

            public function edit(AuthenticatableInterface $user, mixed $resource): Decision
            {
                return Decision::abstain();
            }
        };

        $authorizer = $this->makeAuthorizer('stdClass', $policy);
        $user = new TestUser(id: 1);
        $resource = new \stdClass();

        $decision = $authorizer->inspect($user, 'edit', $resource);

        self::assertTrue($decision->isAbstain());
    }

    public function test_policy_deny_overrides_rbac_allow(): void
    {
        $policy = new class extends Policy {
            public function before(AuthenticatableInterface $identity, string $ability, mixed $resource = null): ?Decision
            {
                return null;
            }

            public function edit(AuthenticatableInterface $user, mixed $resource): Decision
            {
                return Decision::deny('explicitly denied by policy');
            }
        };

        // RBAC has the permission, but policy denies.
        $this->store->setPermissions(1, ['edit']);

        $authorizer = $this->makeAuthorizer('stdClass', $policy);
        $user = new TestUser(id: 1);
        $resource = new \stdClass();

        $decision = $authorizer->inspect($user, 'edit', $resource);

        self::assertTrue($decision->isDenied());
        self::assertSame('explicitly denied by policy', $decision->reason);
    }

    public function test_policy_for_nonexistent_ability_abstains_and_falls_to_rbac(): void
    {
        $policy = new class extends Policy {
            // No method for "unknown" ability.
        };

        $this->store->setPermissions(1, ['unknown']);

        $authorizer = $this->makeAuthorizer('stdClass', $policy);
        $user = new TestUser(id: 1);
        $resource = new \stdClass();

        $decision = $authorizer->inspect($user, 'unknown', $resource);

        self::assertTrue($decision->isAllowed());
    }
}
