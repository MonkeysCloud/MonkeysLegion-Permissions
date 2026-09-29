<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Integration;

use MonkeysLegion\Permissions\AuthorizationManager;
use MonkeysLegion\Permissions\Authorizer;
use MonkeysLegion\Permissions\Cache\CacheLayer;
use MonkeysLegion\Permissions\Decision;
use MonkeysLegion\Permissions\Exceptions\AuthorizationException;
use MonkeysLegion\Permissions\Gate;
use MonkeysLegion\Permissions\Policy\Policy;
use MonkeysLegion\Permissions\Policy\PolicyResolver;
use MonkeysLegion\Permissions\Tests\Stub\InMemoryPermissionStore;
use MonkeysLegion\Permissions\Tests\Stub\TestUser;
use MonkeysLegion\Permissions\Tests\TestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;

/**
 * Integration tests for the full authorization flow:
 * Gate → Policy → RBAC fallback → Deny.
 */
final class AuthorizationFlowTest extends TestCase
{
    private Gate $gate;
    private InMemoryPermissionStore $store;
    private CacheLayer $cache;
    private AuthorizationManager $manager;

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

        $this->rebuildManager();
    }

    private function rebuildManager(): void
    {
        $policyResolver = new PolicyResolver($this->container, $this->policyMap);
        $authorizer = new Authorizer(
            $this->gate,
            $policyResolver,
            $this->store,
            $this->cache,
        );
        $this->manager = new AuthorizationManager($authorizer, $this->gate);
    }

    public function test_full_flow_gate_takes_precedence(): void
    {
        // Gate defined AND permission in store — gate should win.
        $this->gate->define('edit', fn() => false);
        $this->store->setPermissions(1, ['edit']);

        $user = new TestUser(id: 1);

        // Gate denies, so overall deny even though RBAC would allow.
        self::assertFalse($this->manager->can($user, 'edit'));
    }

    public function test_full_flow_falls_through_to_rbac_when_no_gate(): void
    {
        $this->store->setPermissions(1, ['edit']);

        $user = new TestUser(id: 1);

        self::assertTrue($this->manager->can($user, 'edit'));
    }

    public function test_full_flow_denies_when_nothing_matches(): void
    {
        $user = new TestUser(id: 1);

        self::assertFalse($this->manager->can($user, 'unknown-ability'));
    }

    public function test_full_flow_with_resource_passes_resource_to_gate(): void
    {
        $post = new \stdClass();
        $post->ownerId = 1;

        $this->gate->define('update', function ($user, $resource) {
            return $user->getAuthIdentifier() === $resource->ownerId;
        });

        $owner = new TestUser(id: 1);
        $other = new TestUser(id: 2);

        self::assertTrue($this->manager->can($owner, 'update', $post));
        self::assertFalse($this->manager->can($other, 'update', $post));
    }

    public function test_authorize_throws_with_meaningful_message_on_deny(): void
    {
        $this->gate->define('delete', fn() => Decision::deny('only admins can delete'));

        $user = new TestUser();

        try {
            $this->manager->authorize($user, 'delete');
            self::fail('Expected AuthorizationException');
        } catch (AuthorizationException $e) {
            self::assertNotNull($e->decision);
            self::assertTrue($e->decision->isDenied());
            self::assertSame('only admins can delete', $e->decision->reason);
        }
    }

    public function test_tenant_scoped_rbac(): void
    {
        // InMemoryPermissionStore does not filter by tenant (all tenants see same perms).
        // This test verifies that tenant parameter is accepted without error.
        $this->store->setPermissions(1, ['view-reports']);

        $user = new TestUser(id: 1);

        // Permission exists; tenant parameter is passed through without error.
        self::assertTrue($this->manager->can($user, 'view-reports', null, 42));
        self::assertTrue($this->manager->can($user, 'view-reports', null, 99));
    }

    public function test_cache_persists_across_multiple_checks(): void
    {
        $this->store->setPermissions(1, ['edit']);

        $user = new TestUser(id: 1);

        // First call populates cache.
        self::assertTrue($this->manager->can($user, 'edit'));

        // Remove from store — cache should still return true.
        $this->store->clear();

        self::assertTrue($this->manager->can($user, 'edit'));
    }

    public function test_multiple_gates_and_users(): void
    {
        $this->gate->define('admin-only', fn($user) => $user->getAuthIdentifier() === 1);
        $this->gate->define('editor-only', fn($user) => $user->getAuthIdentifier() === 2);

        $admin  = new TestUser(id: 1);
        $editor = new TestUser(id: 2);
        $guest  = new TestUser(id: 3);

        self::assertTrue($this->manager->can($admin, 'admin-only'));
        self::assertFalse($this->manager->can($editor, 'admin-only'));
        self::assertTrue($this->manager->can($editor, 'editor-only'));
        self::assertFalse($this->manager->can($guest, 'admin-only'));
        self::assertFalse($this->manager->can($guest, 'editor-only'));
    }
}
