<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Rule;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Fluent builder for composable authorization rules.
 *
 * Usage:
 *   $canPublishNow = Rule::all([
 *       Rule::userHas('posts.publish'),
 *       Rule::resourceAttribute('status', 'draft'),
 *       Rule::timeOfDay(between: ['09:00', '17:00']),
 *       Rule::not(Rule::userAttribute('locked', true)),
 *   ]);
 *
 *   if ($canPublishNow->evaluate($user, $post)) { ... }
 *
 * Rules serialize to JSON for database persistence and admin-UI editing.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final readonly class Rule
{
    public function __construct(
        private Predicate $predicate,
    ) {}

    // ── Evaluation ─────────────────────────────────────────────

    /**
     * Evaluate this rule against a user and optional resource.
     */
    public function evaluate(AuthenticatableInterface $identity, mixed $resource = null): bool
    {
        return $this->predicate->evaluate($identity, $resource);
    }

    // ── Leaf predicates (static factories) ─────────────────────

    /**
     * User must hold the given permission string.
     */
    public static function userHas(string $permission): self
    {
        return new self(new Predicate(
            type: PredicateType::UserHas,
            params: ['permission' => $permission],
        ));
    }

    /**
     * A user property must equal the expected value.
     */
    public static function userAttribute(string $attribute, mixed $value): self
    {
        return new self(new Predicate(
            type: PredicateType::UserAttribute,
            params: ['attribute' => $attribute, 'value' => $value],
        ));
    }

    /**
     * A resource property must equal the expected value.
     */
    public static function resourceAttribute(string $attribute, mixed $value): self
    {
        return new self(new Predicate(
            type: PredicateType::ResourceAttr,
            params: ['attribute' => $attribute, 'value' => $value],
        ));
    }

    /**
     * Current time must fall within the given window (24h format).
     *
     * @param array{0: string, 1: string} $between ['09:00', '17:00']
     */
    public static function timeOfDay(array $between): self
    {
        return new self(new Predicate(
            type: PredicateType::TimeOfDay,
            params: ['start' => $between[0], 'end' => $between[1]],
        ));
    }

    /**
     * Current day of week must be one of the given days.
     *
     * @param list<int> $days Day numbers (0=Sunday, 6=Saturday)
     */
    public static function dayOfWeek(array $days): self
    {
        return new self(new Predicate(
            type: PredicateType::DayOfWeek,
            params: ['days' => $days],
        ));
    }

    /**
     * Client IP must fall within one of the given CIDR ranges.
     *
     * @param list<string> $ranges CIDR notation strings
     */
    public static function ipRange(array $ranges, ?string $ip = null): self
    {
        $params = ['ranges' => $ranges];
        if ($ip !== null) {
            $params['ip'] = $ip;
        }

        return new self(new Predicate(
            type: PredicateType::IpRange,
            params: $params,
        ));
    }

    /**
     * User must belong to the given tenant.
     */
    public static function tenantIs(int|string $tenantId): self
    {
        return new self(new Predicate(
            type: PredicateType::TenantIs,
            params: ['tenant_id' => $tenantId],
        ));
    }

    /**
     * Ad-hoc callback predicate. NOT serializable to JSON.
     *
     * @param \Closure(AuthenticatableInterface, mixed): bool $callback
     */
    public static function callback(\Closure $callback): self
    {
        return new self(new Predicate(
            type: PredicateType::Callback,
            callback: $callback,
        ));
    }

    // ── Composite predicates ───────────────────────────────────

    /**
     * All child rules must pass (AND).
     *
     * @param list<Rule> $rules
     */
    public static function all(array $rules): self
    {
        return new self(new Predicate(
            type: PredicateType::All,
            children: array_map(
                static fn(Rule $r) => $r->predicate,
                $rules,
            ),
        ));
    }

    /**
     * At least one child rule must pass (OR).
     *
     * @param list<Rule> $rules
     */
    public static function any(array $rules): self
    {
        return new self(new Predicate(
            type: PredicateType::Any,
            children: array_map(
                static fn(Rule $r) => $r->predicate,
                $rules,
            ),
        ));
    }

    /**
     * The child rule must NOT pass (NOT).
     */
    public static function not(Rule $rule): self
    {
        return new self(new Predicate(
            type: PredicateType::Not,
            children: [$rule->predicate],
        ));
    }

    // ── Serialization ──────────────────────────────────────────

    /**
     * Serialize this rule tree to a JSON-safe array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->predicate->toArray();
    }

    /**
     * Reconstruct a Rule from a serialized array.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(Predicate::fromArray($data));
    }

    /**
     * Serialize to JSON string (for DB storage).
     */
    public function toJson(): string
    {
        return $this->predicate->toJson();
    }

    /**
     * Reconstruct from a JSON string (from DB).
     */
    public static function fromJson(string $json): self
    {
        return new self(Predicate::fromJson($json));
    }
}
