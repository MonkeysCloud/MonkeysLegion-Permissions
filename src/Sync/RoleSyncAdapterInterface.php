<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Sync;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Contract for external identity provider role-sync adapters.
 * Implement this interface for LDAP, SAML, OIDC, or any external
 * directory that should feed roles into the permissions system.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
interface RoleSyncAdapterInterface
{
    /**
     * A unique name identifying this adapter (e.g., 'ldap', 'saml', 'okta').
     */
    public function name(): string;

    /**
     * Fetch the role names for a given external user identifier.
     *
     * The returned roles are the canonical external names. The RoleSyncManager
     * will apply the role map to translate them to local role names before syncing.
     *
     * @param string $externalId The user's identifier in the external system
     *                           (e.g., LDAP DN, SAML NameID, email).
     *
     * @return list<string> External role names.
     *
     * @throws SyncException On communication failure with the external provider.
     */
    public function fetchRoles(string $externalId): array;

    /**
     * Test the connection to the external provider.
     *
     * @return bool True if the provider is reachable and authenticated.
     */
    public function healthCheck(): bool;

    /**
     * Return the role mapping configuration.
     *
     * Maps external role names to local role names.
     * Example: ['CN=Admins,OU=Groups,DC=corp' => 'admin', 'CN=Editors' => 'editor']
     *
     * @return array<string, string> External name => local name
     */
    public function roleMap(): array;
}
