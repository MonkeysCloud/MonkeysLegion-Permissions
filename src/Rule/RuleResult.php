<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Rule;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Value object representing the result of a RuleEngine evaluation.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final readonly class RuleResult
{
    private function __construct(
        public bool $isAllowed,
        public bool $isDenied,
        public ?string $ruleName = null,
        public ?string $reason = null,
    ) {}

    public static function allow(): self
    {
        return new self(isAllowed: true, isDenied: false);
    }

    public static function deny(string $ruleName, ?string $reason = null): self
    {
        return new self(isAllowed: false, isDenied: true, ruleName: $ruleName, reason: $reason);
    }

    public static function abstain(): self
    {
        return new self(isAllowed: false, isDenied: false);
    }

    public function isAbstain(): bool
    {
        return !$this->isAllowed && !$this->isDenied;
    }
}
