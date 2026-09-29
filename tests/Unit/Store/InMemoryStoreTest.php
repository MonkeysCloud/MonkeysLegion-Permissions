<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Unit\Store;

use MonkeysLegion\Permissions\Tests\TestCase;
use MonkeysLegion\Permissions\Tests\Stub\InMemoryPermissionStore;
use MonkeysLegion\Permissions\Tests\Stub\TestUser;

final class InMemoryStoreTest extends TestCase
{
    private InMemoryPermissionStore $store;

    protected function setUp(): void
    {
        $this->store = new InMemoryPermissionStore();
    }

    public function test_has_role_returns_false_for_unset_user(): void
    {
        $user = new TestUser(id: 1);

        self::assertFalse($this->store->hasRole($user, 'admin'));
    }

    public function test_has_role_returns_true_after_set_roles(): void
    {
        $user = new TestUser(id: 1);
        $this->store->setRoles(1, ['admin', 'editor']);

        self::assertTrue($this->store->hasRole($user, 'admin'));
        self::assertTrue($this->store->hasRole($user, 'editor'));
        self::assertFalse($this->store->hasRole($user, 'superadmin'));
    }

    public function test_has_permission_returns_false_for_unset_user(): void
    {
        $user = new TestUser(id: 1);

        self::assertFalse($this->store->hasPermission($user, 'edit-post'));
    }

    public function test_has_permission_returns_true_after_set_permissions(): void
    {
        $user = new TestUser(id: 1);
        $this->store->setPermissions(1, ['edit-post', 'delete-post']);

        self::assertTrue($this->store->hasPermission($user, 'edit-post'));
        self::assertTrue($this->store->hasPermission($user, 'delete-post'));
        self::assertFalse($this->store->hasPermission($user, 'create-post'));
    }

    public function test_add_role_appends_without_duplicates(): void
    {
        $this->store->addRole(1, 'admin');
        $this->store->addRole(1, 'admin'); // duplicate
        $this->store->addRole(1, 'editor');

        $user = new TestUser(id: 1);

        self::assertTrue($this->store->hasRole($user, 'admin'));
        self::assertTrue($this->store->hasRole($user, 'editor'));
    }

    public function test_add_permission_appends_without_duplicates(): void
    {
        $this->store->addPermission(1, 'edit');
        $this->store->addPermission(1, 'edit'); // duplicate
        $this->store->addPermission(1, 'delete');

        $user = new TestUser(id: 1);

        self::assertTrue($this->store->hasPermission($user, 'edit'));
        self::assertTrue($this->store->hasPermission($user, 'delete'));
    }

    public function test_clear_resets_all_data(): void
    {
        $this->store->setRoles(1, ['admin']);
        $this->store->setPermissions(1, ['edit']);
        $this->store->clear();

        $user = new TestUser(id: 1);

        self::assertFalse($this->store->hasRole($user, 'admin'));
        self::assertFalse($this->store->hasPermission($user, 'edit'));
    }

    public function test_different_users_are_isolated(): void
    {
        $this->store->setRoles(1, ['admin']);
        $this->store->setRoles(2, ['editor']);

        $user1 = new TestUser(id: 1);
        $user2 = new TestUser(id: 2);

        self::assertTrue($this->store->hasRole($user1, 'admin'));
        self::assertFalse($this->store->hasRole($user2, 'admin'));
        self::assertTrue($this->store->hasRole($user2, 'editor'));
        self::assertFalse($this->store->hasRole($user1, 'editor'));
    }
}
