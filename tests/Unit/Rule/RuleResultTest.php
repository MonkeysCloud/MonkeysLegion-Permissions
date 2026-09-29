<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Unit\Rule;

use MonkeysLegion\Permissions\Rule\RuleResult;
use MonkeysLegion\Permissions\Tests\TestCase;

final class RuleResultTest extends TestCase
{
    public function test_allow_creates_allowed_result(): void
    {
        $r = RuleResult::allow();

        self::assertTrue($r->isAllowed);
        self::assertFalse($r->isDenied);
        self::assertFalse($r->isAbstain());
    }

    public function test_deny_creates_denied_result_with_rule_name(): void
    {
        $r = RuleResult::deny('business-hours-only', 'Outside business hours');

        self::assertFalse($r->isAllowed);
        self::assertTrue($r->isDenied);
        self::assertSame('business-hours-only', $r->ruleName);
        self::assertSame('Outside business hours', $r->reason);
    }

    public function test_deny_without_reason(): void
    {
        $r = RuleResult::deny('some-rule');

        self::assertTrue($r->isDenied);
        self::assertSame('some-rule', $r->ruleName);
        self::assertNull($r->reason);
    }

    public function test_abstain_creates_abstain_result(): void
    {
        $r = RuleResult::abstain();

        self::assertFalse($r->isAllowed);
        self::assertFalse($r->isDenied);
        self::assertTrue($r->isAbstain());
    }

    public function test_abstain_has_no_rule_name(): void
    {
        $r = RuleResult::abstain();

        self::assertNull($r->ruleName);
        self::assertNull($r->reason);
    }
}
