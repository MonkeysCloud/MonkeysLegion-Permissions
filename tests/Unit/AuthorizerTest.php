<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Unit;

use MonkeysLegion\Permissions\Authorizer;
use MonkeysLegion\Permissions\Cache\CacheLayer;
use MonkeysLegion\Permissions\Decision;
use MonkeysLegion\Permissions\Exceptions\AuthorizationException;
use MonkeysLegion\Permissions\Gate;
use MonkeysLegion\Permissions\Policy\Policy;
use MonkeysLegion\Permissions\Policy\PolicyResolver;
use MonkeysLegion\Permissions\Tests\TestCase;
use MonkeysLegion\Permissions\Tests\Stub\InMemoryPermissionStore;
use MonkeysLegion\Permissions\Tests\Stub\TestUser;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;

final class AuthorizerTest extends TestCase
{
    private Authorizer $authorizer;
    private Gate $gate;
    private InMemoryPermissionStore $store;
    private CacheLayer $cache;

    /** @var ContainerInterface&MockObject */
    private ContainerInterface $container;

    /** @var array<string, class-string<Policy>> */
    private array $policyMap = [];

    protected function setUp(): void
    {
        $this->gate = new Gate();
        $this->store = new InMemoryPermissionStore();
        $this->cache = new CacheLayer();
        $this->container = $this->createMock(ContainerInterface::class);
        $this->policyMap = [];

        $policyResolver = new PolicyResolver($this->container, $this->policyMap);

        $this->authorizer = new Authorizer(
            $this->gate,
            $policyResolver,
            $this->store,
            $this->cache,
        );
    }

    private function authorizerWithPolicyMap(array $map): Authorizer
    {
        $policyResolver = new PolicyResolver($this->container, $map);
        return new Authorizer(
            $this->gate,
            $policyResolver,
            $this->store,
            $this->cache,
        );
    }

    // ── inspect: Gate resolution ────────────────────────────────

    public function test_inspect_returns_allow_when_gate_allows(): void
    {
        $this->gate->define('view', fn() => true);
        $user = new TestUser();

        $decision = $this->authorizer->inspect($user, 'view');

        self::assertTrue($decision->isAllowed());
    }

    public function test_inspect_returns_deny_when_gate_denies(): void
    {
        $this->gate->define('view', fn() => false);
        $user = new TestUser();

        $decision = $this->authorizer->inspect($user, 'view');

        self::assertTrue($decision->isDenied());
    }

    // ── inspect: RBAC fallback ──────────────────────────────────

    public function test_inspect_falls_back_to_rbac_permission_when_no_gate(): void
    {
        $this->store->setPermissions(1, ['edit-post']);
        $user = new TestUser(id: 1);

        $decision = $this->authorizer->inspect($user, 'edit-post');

        self::assertTrue($decision->isAllowed());
    }

    public function test_inspect_denies_when_no_gate_no_permission(): void
    {
        $user = new TestUser(id: 1);

        $decision = $this->authorizer->inspect($user, 'edit-post');

        self::assertTrue($decision->isDenied());
    }

    // ── inspect: Policy resolution ──────────────────────────────

    public function test_inspect_uses_policy_when_resource_matches(): void
    {
        $resource = new \stdClass();
        $resourceClass = 'stdClass';

        $policy = new class extends Policy {
            public function update(TestUser $user, $resource): Decision
            {
                return Decision::allow('policy allow');
            }
        };

        $this->container
            ->method('get')
            ->willReturn($policy);

        $authorizer = $this->authorizerWithPolicyMap([
            $resourceClass => $policy::class,
        ]);

        // Gate not defined, policy should be consulted.
        $decision = $authorizer->inspect(new TestUser(), 'update', $resource);

        self::assertTrue($decision->isAllowed());
    }

    public function test_inspect_policy_before_hook_can_short_circuit(): void
    {
        $resource = new \stdClass();

        $policy = new class extends Policy {
            public function before($identity, string $ability, mixed $resource = null): ?Decision
            {
                return Decision::allow('super admin bypass');
            }

            public function update($user, $resource): Decision
            {
                return Decision::deny();
            }
        };

        $this->container->method('get')->willReturn($policy);

        $authorizer = $this->authorizerWithPolicyMap(['stdClass' => $policy::class]);

        $decision = $authorizer->inspect(new TestUser(), 'update', $resource);

        self::assertTrue($decision->isAllowed());
        self::assertSame('super admin bypass', $decision->reason);
    }

    public function test_inspect_policy_before_returns_null_continues_to_method(): void
    {
        $resource = new \stdClass();

        $policy = new class extends Policy {
            public function before($identity, string $ability, mixed $resource = null): ?Decision
            {
                return null; // Continue to specific method.
            }

            public function update($user, $resource): Decision
            {
                return Decision::deny('not allowed by policy');
            }
        };

        $this->container->method('get')->willReturn($policy);

        $authorizer = $this->authorizerWithPolicyMap(['stdClass' => $policy::class]);

        $decision = $authorizer->inspect(new TestUser(), 'update', $resource);

        self::assertTrue($decision->isDenied());
        self::assertSame('not allowed by policy', $decision->reason);
    }

    // ── authorize ───────────────────────────────────────────────

    public function test_authorize_returns_true_when_allowed(): void
    {
        $this->gate->define('view', fn() => true);

        $result = $this->authorizer->authorize(new TestUser(), 'view');

        self::assertTrue($result);
    }

    public function test_authorize_throws_when_denied(): void
    {
        $this->gate->define('view', fn() => false);

        $this->expectException(AuthorizationException::class);

        $this->authorizer->authorize(new TestUser(), 'view');
    }

    public function test_authorize_throws_when_abstain(): void
    {
        // No gate, no permission, no policy → deny (abstain treated as deny).
        $this->expectException(AuthorizationException::class);

        $this->authorizer->authorize(new TestUser(), 'unknown');
    }

    // ── hasRole ─────────────────────────────────────────────────

    public function test_has_role_returns_true_when_store_has_role(): void
    {
        $this->store->setRoles(1, ['admin']);
        $user = new TestUser(id: 1);

        self::assertTrue($this->authorizer->hasRole($user, 'admin'));
    }

    public function test_has_role_returns_false_when_store_lacks_role(): void
    {
        $user = new TestUser(id: 1);

        self::assertFalse($this->authorizer->hasRole($user, 'admin'));
    }

    // ── hasPermission ───────────────────────────────────────────

    public function test_has_permission_returns_true_when_store_has_permission(): void
    {
        $this->store->setPermissions(1, ['edit-post']);
        $user = new TestUser(id: 1);

        self::assertTrue($this->authorizer->hasPermission($user, 'edit-post'));
    }

    public function test_has_permission_returns_false_when_store_lacks_permission(): void
    {
        $user = new TestUser(id: 1);

        self::assertFalse($this->authorizer->hasPermission($user, 'edit-post'));
    }

    // ── Caching ─────────────────────────────────────────────────

    public function test_has_permission_is_cached(): void
    {
        $user = new TestUser(id: 1);

        // First call — store says false.
        self::assertFalse($this->authorizer->hasPermission($user, 'edit-post'));

        // Add permission to store — but cache should return old result.
        $this->store->setPermissions(1, ['edit-post']);

        self::assertFalse($this->authorizer->hasPermission($user, 'edit-post'));
    }

    public function test_cache_invalidation_refreshes_result(): void
    {
        $user = new TestUser(id: 1);

        self::assertFalse($this->authorizer->hasPermission($user, 'edit-post'));

        // Invalidate cache.
        $this->cache->invalidate("perm_1_edit-post_");

        $this->store->setPermissions(1, ['edit-post']);

        self::assertTrue($this->authorizer->hasPermission($user, 'edit-post'));
    }
}
