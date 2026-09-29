<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Unit;

use MonkeysLegion\Permissions\AuthorizationManager;
use MonkeysLegion\Permissions\Authorizer;
use MonkeysLegion\Permissions\Cache\CacheLayer;
use MonkeysLegion\Permissions\Gate;
use MonkeysLegion\Permissions\Policy\PolicyResolver;
use MonkeysLegion\Permissions\Tests\TestCase;
use MonkeysLegion\Permissions\Tests\Stub\InMemoryPermissionStore;
use MonkeysLegion\Permissions\Tests\Stub\TestUser;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;

final class AuthorizationManagerTest extends TestCase
{
    private AuthorizationManager $manager;
    private Authorizer $authorizer;
    private Gate $gate;
    private InMemoryPermissionStore $store;

    protected function setUp(): void
    {
        $this->gate = new Gate();
        $this->store = new InMemoryPermissionStore();

        /** @var ContainerInterface&MockObject $container */
        $container = $this->createMock(ContainerInterface::class);
        $policyResolver = new PolicyResolver($container, []);
        $cache = new CacheLayer();

        $this->authorizer = new Authorizer(
            $this->gate,
            $policyResolver,
            $this->store,
            $cache,
        );

        $this->manager = new AuthorizationManager($this->authorizer, $this->gate);
    }

    public function test_can_returns_true_when_gate_allows(): void
    {
        $this->gate->define('view-dashboard', fn() => true);
        $user = new TestUser();

        self::assertTrue($this->manager->can($user, 'view-dashboard'));
    }

    public function test_can_returns_false_when_gate_denies(): void
    {
        $this->gate->define('view-dashboard', fn() => false);
        $user = new TestUser();

        self::assertFalse($this->manager->can($user, 'view-dashboard'));
    }

    public function test_cannot_is_inverse_of_can(): void
    {
        $this->gate->define('view-dashboard', fn() => false);
        $user = new TestUser();

        self::assertTrue($this->manager->cannot($user, 'view-dashboard'));
    }

    public function test_authorize_does_not_throw_when_allowed(): void
    {
        $this->gate->define('view-dashboard', fn() => true);
        $user = new TestUser();

        $this->manager->authorize($user, 'view-dashboard');

        // No exception thrown = pass
        $this->expectNotToPerformAssertions();
    }

    public function test_authorize_throws_when_denied(): void
    {
        $this->gate->define('view-dashboard', fn() => false);
        $user = new TestUser();

        $this->expectException(\MonkeysLegion\Permissions\Exceptions\AuthorizationException::class);

        $this->manager->authorize($user, 'view-dashboard');
    }

    public function test_define_delegates_to_gate(): void
    {
        $this->manager->define('custom-ability', fn() => true);

        self::assertTrue($this->gate->has('custom-ability'));
    }

    public function test_can_with_resource_passes_to_gate(): void
    {
        $received = null;
        $this->gate->define('update-post', function ($user, $post) use (&$received) {
            $received = $post;
            return $user->getAuthIdentifier() === $post->ownerId;
        });

        $user = new TestUser(id: 1);
        $post = new \stdClass();
        $post->ownerId = 1;

        self::assertTrue($this->manager->can($user, 'update-post', $post));
        self::assertSame($post, $received);
    }

    public function test_can_with_tenant_scoping(): void
    {
        $this->store->setPermissions(1, ['view-reports']);

        $user = new TestUser(id: 1);

        // No gate defined — falls through to RBAC.
        self::assertTrue($this->manager->can($user, 'view-reports', null, 42));
    }

    public function test_can_returns_false_when_no_gate_no_permission(): void
    {
        $user = new TestUser(id: 1);

        // No gate defined, no permission in store.
        self::assertFalse($this->manager->can($user, 'do-something'));
    }
}
