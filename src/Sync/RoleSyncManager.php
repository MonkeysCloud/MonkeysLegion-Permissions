<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Sync;

use MonkeysLegion\Database\Contracts\ConnectionManagerInterface;
use MonkeysLegion\Permissions\Event\RolesSynced;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Orchestrates role synchronization from external identity providers
 * (LDAP, SAML, OIDC) into the local permission tables.
 *
 * Supports multiple adapters and configurable merge strategies.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class RoleSyncManager
{
    /** @var array<string, RoleSyncAdapterInterface> */
    private array $adapters = [];

    public function __construct(
        private readonly ConnectionManagerInterface $db,
        private readonly SyncStrategy $defaultStrategy = SyncStrategy::Additive,
        private readonly ?EventDispatcherInterface $events = null,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    // ── Adapter Registration ───────────────────────────────────

    /**
     * Register an external sync adapter.
     */
    public function registerAdapter(RoleSyncAdapterInterface $adapter): void
    {
        $this->adapters[$adapter->name()] = $adapter;
    }

    /**
     * Get a registered adapter by name.
     */
    public function adapter(string $name): ?RoleSyncAdapterInterface
    {
        return $this->adapters[$name] ?? null;
    }

    /**
     * List all registered adapter names.
     *
     * @return list<string>
     */
    public function adapterNames(): array
    {
        return array_keys($this->adapters);
    }

    // ── Sync Operations ────────────────────────────────────────

    /**
     * Sync roles for a single user from a specific adapter.
     *
     * @param string             $userId      Local user identifier.
     * @param string             $externalId  User's identifier in the external system.
     * @param string             $adapterName Which adapter to use.
     * @param SyncStrategy|null  $strategy    Override the default strategy.
     * @param int|string|null    $tenantId    Optional tenant scope.
     */
    public function syncUser(
        string $userId,
        string $externalId,
        string $adapterName,
        ?SyncStrategy $strategy = null,
        int|string|null $tenantId = null,
    ): SyncResult {
        $adapter = $this->adapters[$adapterName] ?? null;
        if ($adapter === null) {
            return new SyncResult(
                userId: $userId,
                providerName: $adapterName,
                strategy: $strategy ?? $this->defaultStrategy,
                errors: ["Adapter '{$adapterName}' is not registered."],
            );
        }

        $effectiveStrategy = $strategy ?? $this->defaultStrategy;

        try {
            $externalRoles = $adapter->fetchRoles($externalId);
        } catch (SyncException $e) {
            $this->logger?->error("Role sync failed for user {$userId}: {$e->getMessage()}", [
                'adapter'    => $adapterName,
                'externalId' => $externalId,
            ]);

            return new SyncResult(
                userId: $userId,
                providerName: $adapterName,
                strategy: $effectiveStrategy,
                errors: [$e->getMessage()],
            );
        }

        // Map external roles to local names
        $roleMap = $adapter->roleMap();
        $mappedRoles = $this->mapRoles($externalRoles, $roleMap);

        // Get current local roles
        $currentRoles = $this->getCurrentRoles($userId, $tenantId);

        // Apply sync strategy
        $result = $this->applyStrategy(
            $userId,
            $adapterName,
            $effectiveStrategy,
            $currentRoles,
            $mappedRoles,
            $tenantId,
        );

        // Dispatch event
        $this->events?->dispatch(new RolesSynced(result: $result));

        $this->logger?->info($result->summary());

        return $result;
    }

    /**
     * Sync roles for a user across all registered adapters.
     *
     * @param string                          $userId     Local user identifier.
     * @param array<string, string>           $idMap      Adapter name => external ID.
     * @param SyncStrategy|null               $strategy   Override the default strategy.
     * @param int|string|null                 $tenantId   Optional tenant scope.
     *
     * @return list<SyncResult>
     */
    public function syncUserAll(
        string $userId,
        array $idMap,
        ?SyncStrategy $strategy = null,
        int|string|null $tenantId = null,
    ): array {
        $results = [];

        foreach ($idMap as $adapterName => $externalId) {
            $results[] = $this->syncUser($userId, $externalId, $adapterName, $strategy, $tenantId);
        }

        return $results;
    }

    /**
     * Run a health check across all registered adapters.
     *
     * @return array<string, bool> Adapter name => healthy
     */
    public function healthCheckAll(): array
    {
        $results = [];
        foreach ($this->adapters as $name => $adapter) {
            $results[$name] = $adapter->healthCheck();
        }
        return $results;
    }

    // ── Strategy Logic ─────────────────────────────────────────

    /**
     * @param list<string> $currentRoles  Local role names the user currently has.
     * @param list<string> $externalRoles Mapped local role names from the external source.
     */
    private function applyStrategy(
        string $userId,
        string $adapterName,
        SyncStrategy $strategy,
        array $currentRoles,
        array $externalRoles,
        int|string|null $tenantId,
    ): SyncResult {
        $added = [];
        $removed = [];
        $unchanged = [];
        $skipped = [];
        $errors = [];

        $localExistingRoles = $this->getAllLocalRoleNames();

        match ($strategy) {
            SyncStrategy::Additive => $this->strategyAdditive(
                $currentRoles, $externalRoles, $localExistingRoles,
                $added, $unchanged, $skipped,
            ),
            SyncStrategy::Replace, SyncStrategy::Merge => $this->strategyReplace(
                $currentRoles, $externalRoles, $localExistingRoles,
                $added, $removed, $unchanged, $skipped,
            ),
            SyncStrategy::IntersectLocal => $this->strategyIntersect(
                $currentRoles, $externalRoles, $localExistingRoles,
                $added, $unchanged, $skipped,
            ),
        };

        // Execute DB changes
        foreach ($added as $role) {
            try {
                $this->assignRole($userId, $role, $tenantId);
            } catch (\Throwable $e) {
                $errors[] = "Failed to assign role '{$role}': {$e->getMessage()}";
            }
        }

        foreach ($removed as $role) {
            try {
                $this->revokeRole($userId, $role, $tenantId);
            } catch (\Throwable $e) {
                $errors[] = "Failed to revoke role '{$role}': {$e->getMessage()}";
            }
        }

        return new SyncResult(
            userId: $userId,
            providerName: $adapterName,
            strategy: $strategy,
            added: $added,
            removed: $removed,
            unchanged: $unchanged,
            skipped: $skipped,
            errors: $errors,
        );
    }

    /**
     * Additive: only add missing roles, never remove.
     *
     * @param list<string> $current
     * @param list<string> $external
     * @param list<string> $localExisting
     * @param list<string> $added
     * @param list<string> $unchanged
     * @param list<string> $skipped
     */
    private function strategyAdditive(
        array $current,
        array $external,
        array $localExisting,
        array &$added,
        array &$unchanged,
        array &$skipped,
    ): void {
        foreach ($external as $role) {
            if (!in_array($role, $localExisting, true)) {
                $skipped[] = $role;
            } elseif (in_array($role, $current, true)) {
                $unchanged[] = $role;
            } else {
                $added[] = $role;
            }
        }
    }

    /**
     * Replace/Merge: mirror external state — add missing, remove extras.
     *
     * @param list<string> $current
     * @param list<string> $external
     * @param list<string> $localExisting
     * @param list<string> $added
     * @param list<string> $removed
     * @param list<string> $unchanged
     * @param list<string> $skipped
     */
    private function strategyReplace(
        array $current,
        array $external,
        array $localExisting,
        array &$added,
        array &$removed,
        array &$unchanged,
        array &$skipped,
    ): void {
        // Add roles in external but not in current
        foreach ($external as $role) {
            if (!in_array($role, $localExisting, true)) {
                $skipped[] = $role;
            } elseif (in_array($role, $current, true)) {
                $unchanged[] = $role;
            } else {
                $added[] = $role;
            }
        }

        // Remove roles in current but not in external
        foreach ($current as $role) {
            if (!in_array($role, $external, true)) {
                $removed[] = $role;
            }
        }
    }

    /**
     * Intersect: only sync roles that exist locally.
     *
     * @param list<string> $current
     * @param list<string> $external
     * @param list<string> $localExisting
     * @param list<string> $added
     * @param list<string> $unchanged
     * @param list<string> $skipped
     */
    private function strategyIntersect(
        array $current,
        array $external,
        array $localExisting,
        array &$added,
        array &$unchanged,
        array &$skipped,
    ): void {
        foreach ($external as $role) {
            if (!in_array($role, $localExisting, true)) {
                $skipped[] = $role;
            } elseif (in_array($role, $current, true)) {
                $unchanged[] = $role;
            } else {
                $added[] = $role;
            }
        }
    }

    // ── Database helpers ────────────────────────────────────────

    /**
     * Map external role names to local role names using the adapter's role map.
     *
     * @param list<string>          $externalRoles
     * @param array<string, string> $roleMap
     *
     * @return list<string>
     */
    private function mapRoles(array $externalRoles, array $roleMap): array
    {
        if ($roleMap === []) {
            return $externalRoles;
        }

        $mapped = [];
        foreach ($externalRoles as $externalRole) {
            if (isset($roleMap[$externalRole])) {
                $mapped[] = $roleMap[$externalRole];
            } else {
                // Pass through unmapped roles as-is
                $mapped[] = $externalRole;
            }
        }

        return array_values(array_unique($mapped));
    }

    /**
     * Get current local role names for a user.
     *
     * @return list<string>
     */
    private function getCurrentRoles(string $userId, int|string|null $tenantId): array
    {
        $sql = "SELECT r.name FROM perm_user_roles ur
                JOIN perm_roles r ON ur.role_id = r.id
                WHERE ur.user_id = :user_id";
        $params = ['user_id' => $userId];

        if ($tenantId !== null) {
            $sql .= " AND ur.tenant_id = :tenant";
            $params['tenant'] = $tenantId;
        }

        $stmt = $this->db->connection()->query($sql, $params);
        $rows = $stmt->fetchAll(\PDO::FETCH_COLUMN);

        $result = [];
        foreach ($rows as $row) {
            if (is_string($row)) {
                $result[] = $row;
            }
        }

        return $result;
    }

    /**
     * Get all role names defined in the local database.
     *
     * @return list<string>
     */
    private function getAllLocalRoleNames(): array
    {
        $stmt = $this->db->connection()->query("SELECT name FROM perm_roles", []);
        $rows = $stmt->fetchAll(\PDO::FETCH_COLUMN);

        $result = [];
        foreach ($rows as $row) {
            if (is_string($row)) {
                $result[] = $row;
            }
        }

        return $result;
    }

    private function assignRole(string $userId, string $roleName, int|string|null $tenantId): void
    {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        // Resolve role ID
        $stmt = $this->db->connection()->query(
            "SELECT id FROM perm_roles WHERE name = :name",
            ['name' => $roleName],
        );
        $roleId = $stmt->fetchColumn();

        if ($roleId === false) {
            throw new \RuntimeException("Role '{$roleName}' does not exist in perm_roles.");
        }

        $this->db->connection()->execute(
            "INSERT INTO perm_user_roles (user_id, role_id, tenant_id, granted_by, granted_at)
             VALUES (:user_id, :role_id, :tenant_id, :granted_by, :granted_at)",
            [
                'user_id'    => $userId,
                'role_id'    => $roleId,
                'tenant_id'  => $tenantId,
                'granted_by' => 'sync',
                'granted_at' => $now,
            ],
        );
    }

    private function revokeRole(string $userId, string $roleName, int|string|null $tenantId): void
    {
        $sql = "DELETE FROM perm_user_roles
                WHERE user_id = :user_id
                  AND role_id = (SELECT id FROM perm_roles WHERE name = :role_name)";
        $params = [
            'user_id'   => $userId,
            'role_name' => $roleName,
        ];

        if ($tenantId !== null) {
            $sql .= " AND tenant_id = :tenant";
            $params['tenant'] = $tenantId;
        }

        $this->db->connection()->execute($sql, $params);
    }
}
