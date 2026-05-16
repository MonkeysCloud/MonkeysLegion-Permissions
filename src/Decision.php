<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Value object representing an authorization decision.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final readonly class Decision
{
    private function __construct(
        public bool $isAllowed,
        public bool $isDenied,
        public ?string $reason = null,
    ) {}

    /**
     * Create an allowed decision.
     */
    public static function allow(?string $reason = null): self
    {
        return new self(isAllowed: true, isDenied: false, reason: $reason);
    }

    /**
     * Create a denied decision.
     */
    public static function deny(?string $reason = null): self
    {
        return new self(isAllowed: false, isDenied: true, reason: $reason);
    }

    /**
     * Create an abstained decision (neither explicitly allowed nor denied).
     * The evaluation engine will continue to the next policy.
     */
    public static function abstain(?string $reason = null): self
    {
        return new self(isAllowed: false, isDenied: false, reason: $reason);
    }

    /**
     * Create a decision based on a boolean condition.
     */
    public static function when(bool $condition, ?string $allowReason = null, ?string $denyReason = null): self
    {
        return $condition 
            ? self::allow($allowReason) 
            : self::deny($denyReason);
    }

    /**
     * Check if the decision is an explicit allow.
     */
    public function isAllowed(): bool
    {
        return $this->isAllowed;
    }

    /**
     * Check if the decision is an explicit deny.
     */
    public function isDenied(): bool
    {
        return $this->isDenied;
    }

    /**
     * Check if the decision is an abstain.
     */
    public function isAbstain(): bool
    {
        return !$this->isAllowed && !$this->isDenied;
    }
}
