<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Store;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Database\Contracts\ConnectionManagerInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Database implementation of the PermissionStore.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class DatabaseStore implements PermissionStoreInterface
{
    public function __construct(
        private readonly ConnectionManagerInterface $db,
    ) {}

    public function hasRole(AuthenticatableInterface $identity, string $role, int|string|null $tenant = null): bool
    {
        $userId = $identity->getAuthIdentifier();
        
        $sql = "SELECT 1 FROM perm_user_roles ur 
                JOIN perm_roles r ON ur.role_id = r.id 
                WHERE ur.user_id = :user_id AND r.name = :role_name";
        $params = [
            'user_id' => $userId,
            'role_name' => $role,
        ];

        if ($tenant !== null) {
            $sql .= " AND ur.tenant_id = :tenant";
            $params['tenant'] = $tenant;
        }

        $stmt = $this->db->connection()->query($sql, $params);
        return (bool) $stmt->fetchColumn();
    }

    public function hasPermission(AuthenticatableInterface $identity, string $permission, int|string|null $tenant = null): bool
    {
        $userId = $identity->getAuthIdentifier();

        // 1. Check direct permissions
        $sqlDirect = "SELECT 1 FROM perm_user_permissions up 
                      JOIN perm_permissions p ON up.permission_id = p.id 
                      WHERE up.user_id = :user_id AND p.name = :perm_name";
        $paramsDirect = [
            'user_id' => $userId,
            'perm_name' => $permission,
        ];

        if ($tenant !== null) {
            $sqlDirect .= " AND up.tenant_id = :tenant";
            $paramsDirect['tenant'] = $tenant;
        }

        $stmtDirect = $this->db->connection()->query($sqlDirect, $paramsDirect);
        if ($stmtDirect->fetchColumn()) {
            return true;
        }

        // 2. Check permissions via roles
        $sqlRole = "SELECT 1 FROM perm_user_roles ur 
                    JOIN perm_roles r ON ur.role_id = r.id 
                    JOIN perm_role_permissions rp ON r.id = rp.role_id 
                    JOIN perm_permissions p ON rp.permission_id = p.id 
                    WHERE ur.user_id = :user_id AND p.name = :perm_name";
        
        $paramsRole = [
            'user_id' => $userId,
            'perm_name' => $permission,
        ];

        if ($tenant !== null) {
            $sqlRole .= " AND ur.tenant_id = :tenant";
            $paramsRole['tenant'] = $tenant;
        }

        $stmtRole = $this->db->connection()->query($sqlRole, $paramsRole);
        return (bool) $stmtRole->fetchColumn();
    }
}
