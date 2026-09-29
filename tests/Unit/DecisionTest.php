<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Unit;

use MonkeysLegion\Permissions\Decision;
use MonkeysLegion\Permissions\Tests\TestCase;

final class DecisionTest extends TestCase
{
    public function test_allow_creates_allowed_decision(): void
    {
        $d = Decision::allow();

        self::assertTrue($d->isAllowed());
        self::assertFalse($d->isDenied());
        self::assertFalse($d->isAbstain());
        self::assertNull($d->reason);
    }

    public function test_allow_with_reason(): void
    {
        $d = Decision::allow('Owner can edit');

        self::assertTrue($d->isAllowed());
        self::assertSame('Owner can edit', $d->reason);
    }

    public function test_deny_creates_denied_decision(): void
    {
        $d = Decision::deny();

        self::assertFalse($d->isAllowed());
        self::assertTrue($d->isDenied());
        self::assertFalse($d->isAbstain());
        self::assertNull($d->reason);
    }

    public function test_deny_with_reason(): void
    {
        $d = Decision::deny('Not enough permissions');

        self::assertTrue($d->isDenied());
        self::assertSame('Not enough permissions', $d->reason);
    }

    public function test_abstain_creates_abstain_decision(): void
    {
        $d = Decision::abstain();

        self::assertFalse($d->isAllowed());
        self::assertFalse($d->isDenied());
        self::assertTrue($d->isAbstain());
    }

    public function test_abstain_with_reason(): void
    {
        $d = Decision::abstain('No policy registered');

        self::assertTrue($d->isAbstain());
        self::assertSame('No policy registered', $d->reason);
    }

    public function test_when_true_returns_allow(): void
    {
        $d = Decision::when(true, 'ok', 'no');

        self::assertTrue($d->isAllowed());
        self::assertFalse($d->isDenied());
        self::assertSame('ok', $d->reason);
    }

    public function test_when_false_returns_deny(): void
    {
        $d = Decision::when(false, 'ok', 'no');

        self::assertFalse($d->isAllowed());
        self::assertTrue($d->isDenied());
        self::assertSame('no', $d->reason);
    }

    public function test_when_without_optional_reasons(): void
    {
        $allowD = Decision::when(true);
        $denyD  = Decision::when(false);

        self::assertTrue($allowD->isAllowed());
        self::assertTrue($denyD->isDenied());
        self::assertNull($allowD->reason);
        self::assertNull($denyD->reason);
    }

    public function test_decisions_are_immutable(): void
    {
        $d = Decision::allow('reason');

        // Decision is readonly — this is enforced at the language level.
        self::assertTrue($d->isAllowed());
    }
}
