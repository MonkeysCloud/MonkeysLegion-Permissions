<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Rule;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Database\Contracts\ConnectionManagerInterface;
use MonkeysLegion\Permissions\Cache\CacheLayer;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Loads StoredRules from the database, deserializes their predicate trees,
 * and evaluates them against user/resource pairs.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class RuleEngine
{
    public function __construct(
        private readonly ConnectionManagerInterface $db,
        private readonly CacheLayer $cache,
    ) {}

    /**
     * Evaluate all active rules matching the given entity class and ability.
     *
     * Rules are evaluated in priority order (descending). The first rule
     * that returns false causes an immediate deny.
     *
     * @param AuthenticatableInterface $identity   The acting user.
     * @param string                   $ability    The action being performed.
     * @param mixed                    $resource   The entity being acted upon.
     * @param int|string|null          $tenant     Optional tenant scope.
     *
     * @return RuleResult
     */
    public function evaluate(
        AuthenticatableInterface $identity,
        string $ability,
        mixed $resource = null,
        int|string|null $tenant = null,
    ): RuleResult {
        $entityClass = $resource !== null
            ? (is_object($resource) ? get_class($resource) : (is_string($resource) ? $resource : ''))
            : '';

        $rules = $this->loadRules($entityClass, $ability, $tenant);

        if ($rules === []) {
            return RuleResult::abstain();
        }

        foreach ($rules as $rule) {
            $predicate = $this->hydrateRule($rule);
            if ($predicate === null) {
                continue;
            }

            $passed = $predicate->evaluate($identity, $resource);
            if (!$passed) {
                $ruleName = isset($rule['name']) && is_string($rule['name']) ? $rule['name'] : 'unknown';
                return RuleResult::deny(
                    $ruleName,
                    "Rule '{$ruleName}' evaluated to false.",
                );
            }
        }

        return RuleResult::allow();
    }

    /**
     * Load active rules from the database for a given entity class and ability.
     *
     * @return list<array<string, mixed>>
     */
    private function loadRules(string $entityClass, string $ability, int|string|null $tenant): array
    {
        $cacheKey = "rules_{$entityClass}_{$ability}_{$tenant}";

        /** @var list<array<string, mixed>> $result */
        $result = $this->cache->get($cacheKey, function () use ($entityClass, $ability, $tenant) {
            return $this->queryRules($entityClass, $ability, $tenant);
        });

        return $result;
    }

    /**
     * Execute the database query for rules.
     *
     * @return list<array<string, mixed>>
     */
    private function queryRules(string $entityClass, string $ability, int|string|null $tenant): array
    {
        $sql = "SELECT id, name, predicate_json, priority, expires_at
                FROM perm_rules
                WHERE is_active = 1
                  AND (entity_class = :entity_class OR entity_class IS NULL)
                  AND (ability = :ability OR ability IS NULL)
                  AND (expires_at IS NULL OR expires_at > :now)";

        $params = [
            'entity_class' => $entityClass,
            'ability'      => $ability,
            'now'          => (new \DateTimeImmutable())->format('Y-m-d H:i:s'),
        ];

        if ($tenant !== null) {
            $sql .= " AND (tenant_id = :tenant OR tenant_id IS NULL)";
            $params['tenant'] = $tenant;
        } else {
            $sql .= " AND tenant_id IS NULL";
        }

        $sql .= " ORDER BY priority DESC";

        $stmt = $this->db->connection()->query($sql, $params);
        /** @var list<array<string, mixed>> $rows */
        $rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        return $rows;
    }

    /**
     * Hydrate a Predicate tree from a stored rule row.
     *
     * @param array<string, mixed> $row
     */
    private function hydrateRule(array $row): ?Predicate
    {
        $jsonRaw = $row['predicate_json'] ?? '';
        $json = is_string($jsonRaw) ? $jsonRaw : '';
        if ($json === '') {
            return null;
        }

        try {
            return Predicate::fromJson($json);
        } catch (\JsonException) {
            return null;
        }
    }
}
