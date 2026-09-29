<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Unit;

use MonkeysLegion\Permissions\Attributes\Authorize;
use MonkeysLegion\Permissions\Attributes\Gate;
use MonkeysLegion\Permissions\Attributes\RequiresPermission;
use MonkeysLegion\Permissions\Attributes\RequiresRole;
use MonkeysLegion\Permissions\Tests\TestCase;

final class AttributeTest extends TestCase
{
    public function test_authorize_attribute_stores_properties(): void
    {
        $attr = new Authorize(ability: 'update', resource: 'App\Entity\Post', paramName: 'id');

        self::assertSame('update', $attr->ability);
        self::assertSame('App\Entity\Post', $attr->resource);
        self::assertSame('id', $attr->paramName);
    }

    public function test_authorize_attribute_param_name_defaults_to_null(): void
    {
        $attr = new Authorize('view', 'App\Entity\Post');

        self::assertNull($attr->paramName);
    }

    public function test_gate_attribute_stores_name(): void
    {
        $attr = new Gate('admin-only');

        self::assertSame('admin-only', $attr->name);
    }

    public function test_requires_permission_with_single_permission(): void
    {
        $attr = new RequiresPermission(permission: 'edit-post');

        self::assertSame('edit-post', $attr->permission);
        self::assertSame([], $attr->allOf);
        self::assertSame([], $attr->anyOf);
        self::assertNull($attr->tenant);
    }

    public function test_requires_permission_with_all_of(): void
    {
        $attr = new RequiresPermission(allOf: ['read', 'write']);

        self::assertNull($attr->permission);
        self::assertSame(['read', 'write'], $attr->allOf);
    }

    public function test_requires_permission_with_any_of(): void
    {
        $attr = new RequiresPermission(anyOf: ['read', 'write']);

        self::assertSame(['read', 'write'], $attr->anyOf);
    }

    public function test_requires_permission_with_tenant(): void
    {
        $attr = new RequiresPermission(permission: 'view', tenant: 'acme');

        self::assertSame('acme', $attr->tenant);
    }

    public function test_requires_permission_throws_when_no_permission_specified(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one permission');

        new RequiresPermission();
    }

    public function test_requires_role_with_single_role(): void
    {
        $attr = new RequiresRole(role: 'admin');

        self::assertSame('admin', $attr->role);
        self::assertSame([], $attr->allOf);
        self::assertSame([], $attr->anyOf);
        self::assertNull($attr->tenant);
    }

    public function test_requires_role_with_all_of(): void
    {
        $attr = new RequiresRole(allOf: ['admin', 'editor']);

        self::assertSame(['admin', 'editor'], $attr->allOf);
    }

    public function test_requires_role_with_any_of(): void
    {
        $attr = new RequiresRole(anyOf: ['admin', 'editor']);

        self::assertSame(['admin', 'editor'], $attr->anyOf);
    }

    public function test_requires_role_with_tenant(): void
    {
        $attr = new RequiresRole(role: 'admin', tenant: 'acme');

        self::assertSame('acme', $attr->tenant);
    }

    public function test_requires_role_throws_when_no_role_specified(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one role');

        new RequiresRole();
    }
}
