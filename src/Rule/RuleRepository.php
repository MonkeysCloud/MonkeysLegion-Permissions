<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Rule;

use MonkeysLegion\Database\Contracts\ConnectionManagerInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Repository for CRUD operations on StoredRules.
 * Provides the admin-UI hooks for managing database-stored authorization rules.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class RuleRepository
{
    public function __construct(
        private readonly ConnectionManagerInterface $db,
    ) {}

    /**
     * Create a new stored rule.
     *
     * @param string               $name          Unique rule name.
     * @param Rule                 $rule          The composable rule to persist.
     * @param string|null          $entityClass   Optional entity class constraint.
     * @param string|null          $ability       Optional ability constraint.
     * @param string|null          $description   Human-readable description.
     * @param int                  $priority      Evaluation priority (higher = first).
     * @param string|null          $guard         Guard name scope.
     * @param int|null             $tenantId      Tenant scope.
     * @param \DateTimeImmutable|null $expiresAt  Optional expiration.
     *
     * @return string|false The inserted ID, or false on failure.
     */
    public function create(
        string $name,
        Rule $rule,
        ?string $entityClass = null,
        ?string $ability = null,
        ?string $description = null,
        int $priority = 0,
        ?string $guard = null,
        ?int $tenantId = null,
        ?\DateTimeImmutable $expiresAt = null,
    ): string|false {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        $sql = "INSERT INTO perm_rules 
                (name, description, entity_class, ability, predicate_json, is_active, priority, guard, tenant_id, expires_at, created_at, updated_at) 
                VALUES 
                (:name, :description, :entity_class, :ability, :predicate_json, 1, :priority, :guard, :tenant_id, :expires_at, :now, :now2)";

        $this->db->connection()->execute($sql, [
            'name'           => $name,
            'description'    => $description,
            'entity_class'   => $entityClass,
            'ability'        => $ability,
            'predicate_json' => $rule->toJson(),
            'priority'       => $priority,
            'guard'          => $guard,
            'tenant_id'      => $tenantId,
            'expires_at'     => $expiresAt?->format('Y-m-d H:i:s'),
            'now'            => $now,
            'now2'           => $now,
        ]);

        return $this->db->connection()->lastInsertId();
    }

    /**
     * Update the predicate JSON for an existing rule by name.
     */
    public function updateRule(string $name, Rule $rule): int
    {
        $sql = "UPDATE perm_rules 
                SET predicate_json = :predicate_json, updated_at = :now 
                WHERE name = :name";

        return $this->db->connection()->execute($sql, [
            'predicate_json' => $rule->toJson(),
            'now'            => (new \DateTimeImmutable())->format('Y-m-d H:i:s'),
            'name'           => $name,
        ]);
    }

    /**
     * Activate or deactivate a rule by name.
     */
    public function setActive(string $name, bool $active): int
    {
        $sql = "UPDATE perm_rules 
                SET is_active = :active, updated_at = :now 
                WHERE name = :name";

        return $this->db->connection()->execute($sql, [
            'active' => $active ? 1 : 0,
            'now'    => (new \DateTimeImmutable())->format('Y-m-d H:i:s'),
            'name'   => $name,
        ]);
    }

    /**
     * Delete a rule by name.
     */
    public function delete(string $name): int
    {
        return $this->db->connection()->execute(
            "DELETE FROM perm_rules WHERE name = :name",
            ['name' => $name],
        );
    }

    /**
     * Find a rule by name and return its deserialized Rule object.
     */
    public function findByName(string $name): ?Rule
    {
        $stmt = $this->db->connection()->query(
            "SELECT predicate_json FROM perm_rules WHERE name = :name AND is_active = 1",
            ['name' => $name],
        );

        $json = $stmt->fetchColumn();
        if ($json === false || $json === null) {
            return null;
        }

        return Rule::fromJson((string) $json);
    }

    /**
     * List all rules, optionally filtered by entity class.
     *
     * @return list<array{id: int, name: string, description: ?string, entity_class: ?string, ability: ?string, is_active: bool, priority: int}>
     */
    public function listAll(?string $entityClass = null): array
    {
        $sql = "SELECT id, name, description, entity_class, ability, is_active, priority 
                FROM perm_rules";
        $params = [];

        if ($entityClass !== null) {
            $sql .= " WHERE entity_class = :entity_class";
            $params['entity_class'] = $entityClass;
        }

        $sql .= " ORDER BY priority DESC, name ASC";

        $stmt = $this->db->connection()->query($sql, $params);
        /** @var list<array{id: int, name: string, description: ?string, entity_class: ?string, ability: ?string, is_active: bool, priority: int}> $rows */
        $rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        return $rows;
    }
}
