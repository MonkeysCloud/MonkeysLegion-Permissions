<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Sync\Adapter;

use MonkeysLegion\Permissions\Sync\RoleSyncAdapterInterface;
use MonkeysLegion\Permissions\Sync\SyncException;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * LDAP role-sync adapter.
 *
 * Connects to an LDAP/Active Directory server and fetches group memberships
 * for a given user DN, translating them to local role names via the role map.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class LdapSyncAdapter implements RoleSyncAdapterInterface
{
    /** @var \LDAP\Connection|null */
    private ?\LDAP\Connection $connection = null;

    /**
     * @param string               $host       LDAP server URI (e.g., ldaps://ldap.corp.com:636)
     * @param string               $bindDn     Bind DN for authentication.
     * @param string               $bindPassword  Bind password.
     * @param string               $baseDn     Base DN for group searches.
     * @param string               $groupAttr  Attribute containing group memberships.
     * @param array<string, string> $roleMap   External group DN/CN => local role name.
     */
    public function __construct(
        private readonly string $host,
        private readonly string $bindDn,
        private readonly string $bindPassword,
        private readonly string $baseDn,
        private readonly string $groupAttr = 'memberOf',
        private readonly array $roleMap = [],
    ) {}

    public function name(): string
    {
        return 'ldap';
    }

    public function fetchRoles(string $externalId): array
    {
        $conn = $this->connect();

        // Search for the user entry
        $filter = sprintf('(distinguishedName=%s)', ldap_escape($externalId, '', LDAP_ESCAPE_FILTER));
        $searchResult = @ldap_search($conn, $this->baseDn, $filter, [$this->groupAttr]);

        if ($searchResult === false) {
            throw new SyncException(
                "LDAP search failed: " . ldap_error($conn),
                adapterName: $this->name(),
                externalId: $externalId,
            );
        }

        // ldap_search can return array|LDAP\Result; we need a single Result
        if (is_array($searchResult)) {
            $searchResult = $searchResult[0] ?? null;
            if (!$searchResult instanceof \LDAP\Result) {
                return [];
            }
        }

        $entries = ldap_get_entries($conn, $searchResult);
        if ($entries === false || $entries['count'] === 0) {
            return [];
        }

        $roles = [];
        $entry = $entries[0];

        if (isset($entry[$this->groupAttr]) && is_array($entry[$this->groupAttr])) {
            $countRaw = $entry[$this->groupAttr]['count'] ?? 0;
            $count = is_int($countRaw) ? $countRaw : (is_numeric($countRaw) ? intval($countRaw) : 0);
            for ($i = 0; $i < $count; $i++) {
                $groupDn = $entry[$this->groupAttr][$i] ?? null;
                if (is_string($groupDn) && $groupDn !== '') {
                    $roles[] = $groupDn;
                }
            }
        }

        return $roles;
    }

    public function healthCheck(): bool
    {
        try {
            $this->connect();
            return true;
        } catch (SyncException) {
            return false;
        }
    }

    public function roleMap(): array
    {
        return $this->roleMap;
    }

    // ── Internal ────────────────────────────────────────────────

    private function connect(): \LDAP\Connection
    {
        if ($this->connection !== null) {
            return $this->connection;
        }

        $conn = @ldap_connect($this->host);
        if ($conn === false) {
            throw new SyncException(
                "Cannot connect to LDAP server: {$this->host}",
                adapterName: $this->name(),
            );
        }

        ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($conn, LDAP_OPT_NETWORK_TIMEOUT, 10);

        $bound = @ldap_bind($conn, $this->bindDn, $this->bindPassword);
        if ($bound === false) {
            throw new SyncException(
                "LDAP bind failed: " . ldap_error($conn),
                adapterName: $this->name(),
            );
        }

        $this->connection = $conn;
        return $conn;
    }

    public function __destruct()
    {
        if ($this->connection !== null) {
            @ldap_unbind($this->connection);
            $this->connection = null;
        }
    }
}
