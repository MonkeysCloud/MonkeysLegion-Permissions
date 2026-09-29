<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Unit;

use MonkeysLegion\Permissions\Decision;
use MonkeysLegion\Permissions\Exceptions\AuthorizationException;
use MonkeysLegion\Permissions\Gate;
use MonkeysLegion\Permissions\Tests\TestCase;
use MonkeysLegion\Permissions\Tests\Stub\TestUser;

final class GateTest extends TestCase
{
    private Gate $gate;

    protected function setUp(): void
    {
        $this->gate = new Gate();
    }

    public function test_define_registers_gate(): void
    {
        $this->gate->define('update-post', fn() => true);

        self::assertTrue($this->gate->has('update-post'));
    }

    public function test_has_returns_false_for_undefined_gate(): void
    {
        self::assertFalse($this->gate->has('nonexistent'));
    }

    public function test_inspect_returns_allow_decision_when_callback_returns_true(): void
    {
        $this->gate->define('view-post', fn() => true);
        $user = new TestUser();

        $decision = $this->gate->inspect('view-post', $user);

        self::assertTrue($decision->isAllowed());
    }

    public function test_inspect_returns_deny_decision_when_callback_returns_false(): void
    {
        $this->gate->define('delete-post', fn() => false);
        $user = new TestUser();

        $decision = $this->gate->inspect('delete-post', $user);

        self::assertTrue($decision->isDenied());
    }

    public function test_inspect_returns_decision_object_when_callback_returns_decision(): void
    {
        $this->gate->define('edit-post', fn() => Decision::allow('custom reason'));
        $user = new TestUser();

        $decision = $this->gate->inspect('edit-post', $user);

        self::assertTrue($decision->isAllowed());
        self::assertSame('custom reason', $decision->reason);
    }

    public function test_inspect_passes_arguments_to_callback(): void
    {
        $received = null;
        $this->gate->define('view-post', function ($user, $post) use (&$received) {
            $received = $post;
            return true;
        });

        $user = new TestUser();
        $post = new \stdClass();
        $post->id = 42;

        $this->gate->inspect('view-post', $user, $post);

        self::assertSame($post, $received);
    }

    public function test_inspect_throws_for_undefined_gate(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Gate [missing] is not defined.');

        $this->gate->inspect('missing', new TestUser());
    }

    public function test_authorize_returns_true_when_allowed(): void
    {
        $this->gate->define('view-post', fn() => true);

        $result = $this->gate->authorize('view-post', new TestUser());

        self::assertTrue($result);
    }

    public function test_authorize_throws_when_denied(): void
    {
        $this->gate->define('delete-post', fn() => false);

        $this->expectException(AuthorizationException::class);

        $this->gate->authorize('delete-post', new TestUser());
    }

    public function test_authorize_exception_contains_decision(): void
    {
        $this->gate->define('delete-post', fn() => Decision::deny('not owner'));

        try {
            $this->gate->authorize('delete-post', new TestUser());
            self::fail('Expected AuthorizationException');
        } catch (AuthorizationException $e) {
            self::assertNotNull($e->decision);
            self::assertTrue($e->decision->isDenied());
            self::assertSame('not owner', $e->decision->reason);
        }
    }

    public function test_authorize_passes_callback_decision_reason_to_exception(): void
    {
        $this->gate->define('edit', fn() => false);

        try {
            $this->gate->authorize('edit', new TestUser());
            self::fail('Expected AuthorizationException');
        } catch (AuthorizationException $e) {
            self::assertSame('This action is unauthorized by gate [edit].', $e->getMessage());
        }
    }

    public function test_gate_callback_receives_user_as_first_arg(): void
    {
        $receivedUser = null;
        $this->gate->define('view', function ($user) use (&$receivedUser) {
            $receivedUser = $user;
            return true;
        });

        $user = new TestUser(id: 99);
        $this->gate->inspect('view', $user);

        self::assertSame($user, $receivedUser);
    }
}
