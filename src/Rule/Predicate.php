<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Rule;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * A single evaluatable predicate node in the Rule tree.
 * Predicates are composable and serializable to JSON for DB persistence.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final readonly class Predicate
{
    /**
     * @param PredicateType             $type       The type of predicate.
     * @param array<string, mixed>      $params     Configuration for this predicate.
     * @param list<Predicate>           $children   Child predicates (for composite types: all, any, not).
     * @param (\Closure(AuthenticatableInterface, mixed): bool)|null $callback Runtime callback (non-serializable).
     */
    public function __construct(
        public PredicateType $type,
        public array $params = [],
        public array $children = [],
        private ?\Closure $callback = null,
    ) {}

    /**
     * Evaluate this predicate against a user and optional resource.
     */
    public function evaluate(AuthenticatableInterface $identity, mixed $resource = null): bool
    {
        return match ($this->type) {
            PredicateType::UserHas       => $this->evalUserHas($identity),
            PredicateType::UserAttribute => $this->evalUserAttribute($identity),
            PredicateType::ResourceAttr  => $this->evalResourceAttribute($resource),
            PredicateType::TimeOfDay     => $this->evalTimeOfDay(),
            PredicateType::DayOfWeek     => $this->evalDayOfWeek(),
            PredicateType::IpRange       => $this->evalIpRange(),
            PredicateType::TenantIs      => $this->evalTenantIs($identity),
            PredicateType::Callback      => $this->evalCallback($identity, $resource),
            PredicateType::All           => $this->evalAll($identity, $resource),
            PredicateType::Any           => $this->evalAny($identity, $resource),
            PredicateType::Not           => $this->evalNot($identity, $resource),
        };
    }

    /**
     * Serialize this predicate tree to a JSON-safe array for DB storage.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $data = [
            'type' => $this->type->value,
            'params' => $this->params,
        ];

        if ($this->children !== []) {
            $data['children'] = array_map(
                static fn(Predicate $child) => $child->toArray(),
                $this->children,
            );
        }

        return $data;
    }

    /**
     * Reconstruct a predicate tree from a serialized array.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $typeValue = $data['type'] ?? '';
        $type = PredicateType::from(is_string($typeValue) ? $typeValue : '');
        /** @var array<string, mixed> $params */
        $params = (array) ($data['params'] ?? []);
        /** @var list<array<string, mixed>> $childrenData */
        $childrenData = (array) ($data['children'] ?? []);

        $children = array_map(
            static fn(array $child) => self::fromArray($child),
            $childrenData,
        );

        return new self($type, $params, $children);
    }

    /**
     * Serialize the predicate tree to JSON.
     */
    public function toJson(): string
    {
        $json = json_encode($this->toArray(), JSON_THROW_ON_ERROR);
        return $json;
    }

    /**
     * Reconstruct from a JSON string.
     */
    public static function fromJson(string $json): self
    {
        /** @var array<string, mixed> $data */
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        return self::fromArray($data);
    }

    // ── Evaluation helpers ─────────────────────────────────────

    private function evalUserHas(AuthenticatableInterface $identity): bool
    {
        $permissionRaw = $this->params['permission'] ?? '';
        $permission = is_string($permissionRaw) ? $permissionRaw : '';
        if ($permission === '') {
            return false;
        }

        // Uses the duck-type approach: if the identity has a can() method, use it
        if (method_exists($identity, 'can')) {
            return (bool) $identity->can($permission);
        }

        return false;
    }

    private function evalUserAttribute(AuthenticatableInterface $identity): bool
    {
        $attributeRaw = $this->params['attribute'] ?? '';
        $attribute = is_string($attributeRaw) ? $attributeRaw : '';
        $expected = $this->params['value'] ?? null;

        if ($attribute === '') {
            return false;
        }

        $actual = $this->readProperty($identity, $attribute);
        return $actual === $expected;
    }

    private function evalResourceAttribute(mixed $resource): bool
    {
        if ($resource === null || !is_object($resource)) {
            return false;
        }

        $attributeRaw = $this->params['attribute'] ?? '';
        $attribute = is_string($attributeRaw) ? $attributeRaw : '';
        $expected = $this->params['value'] ?? null;

        if ($attribute === '') {
            return false;
        }

        $actual = $this->readProperty($resource, $attribute);
        return $actual === $expected;
    }

    private function evalTimeOfDay(): bool
    {
        $startRaw = $this->params['start'] ?? '00:00';
        $endRaw   = $this->params['end']   ?? '23:59';
        $start = is_string($startRaw) ? $startRaw : '00:00';
        $end   = is_string($endRaw)   ? $endRaw   : '23:59';
        $now   = date('H:i');

        return $now >= $start && $now <= $end;
    }

    private function evalDayOfWeek(): bool
    {
        /** @var list<int> $days */
        $days = (array) ($this->params['days'] ?? []);
        return in_array((int) date('w'), $days, true);
    }

    private function evalIpRange(): bool
    {
        $ipRaw = $this->params['ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
        $ip = is_string($ipRaw) ? $ipRaw : '127.0.0.1';
        /** @var list<string> $ranges */
        $ranges = (array) ($this->params['ranges'] ?? []);

        foreach ($ranges as $range) {
            if ($this->ipInRange($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    private function evalTenantIs(AuthenticatableInterface $identity): bool
    {
        $expected = $this->params['tenant_id'] ?? null;
        if ($expected === null) {
            return false;
        }

        if (method_exists($identity, 'getTenantId')) {
            return $identity->getTenantId() === $expected;
        }

        return false;
    }

    private function evalCallback(AuthenticatableInterface $identity, mixed $resource): bool
    {
        if ($this->callback === null) {
            return false;
        }

        return ($this->callback)($identity, $resource);
    }

    private function evalAll(AuthenticatableInterface $identity, mixed $resource): bool
    {
        foreach ($this->children as $child) {
            if (!$child->evaluate($identity, $resource)) {
                return false;
            }
        }

        return true;
    }

    private function evalAny(AuthenticatableInterface $identity, mixed $resource): bool
    {
        foreach ($this->children as $child) {
            if ($child->evaluate($identity, $resource)) {
                return true;
            }
        }

        return false;
    }

    private function evalNot(AuthenticatableInterface $identity, mixed $resource): bool
    {
        if ($this->children === []) {
            return true;
        }

        return !$this->children[0]->evaluate($identity, $resource);
    }

    // ── Internal utilities ─────────────────────────────────────

    private function readProperty(object $target, string $property): mixed
    {
        if (property_exists($target, $property)) {
            return $target->{$property};
        }

        $getter = 'get' . ucfirst($property);
        if (method_exists($target, $getter)) {
            return $target->{$getter}();
        }

        return null;
    }

    /**
     * Check if an IP is within a CIDR range.
     */
    private function ipInRange(string $ip, string $range): bool
    {
        if (!str_contains($range, '/')) {
            return $ip === $range;
        }

        [$subnet, $bits] = explode('/', $range, 2);
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = -1 << (32 - (int) $bits);
        return ($ipLong & $mask) === ($subnetLong & $mask);
    }
}
