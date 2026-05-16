<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Sync\Adapter;

use MonkeysLegion\Permissions\Sync\RoleSyncAdapterInterface;
use MonkeysLegion\Permissions\Sync\SyncException;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * SAML role-sync adapter.
 *
 * Extracts role attributes from a SAML assertion response and maps them
 * to local role names. This adapter is stateless — it parses pre-validated
 * assertion data rather than initiating SAML flows.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class SamlSyncAdapter implements RoleSyncAdapterInterface
{
    /**
     * @param string                $idpEntityId  The IdP entity ID for identification.
     * @param string                $roleAttribute SAML attribute name containing roles.
     * @param array<string, string> $roleMap       External SAML role => local role name.
     * @param string|null           $metadataUrl   Optional IdP metadata URL for health checks.
     */
    public function __construct(
        private readonly string $idpEntityId,
        private readonly string $roleAttribute = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
        private readonly array $roleMap = [],
        private readonly ?string $metadataUrl = null,
    ) {}

    /**
     * In-memory assertion data keyed by NameID.
     *
     * Populated by the SAML middleware/callback handler after validating
     * the assertion. The adapter reads from this cache.
     *
     * @var array<string, list<string>>
     */
    private array $assertionCache = [];

    public function name(): string
    {
        return 'saml';
    }

    /**
     * Fetch roles from a previously cached SAML assertion.
     *
     * @param string $externalId The SAML NameID for the user.
     *
     * @return list<string> External role attribute values.
     */
    public function fetchRoles(string $externalId): array
    {
        if (!isset($this->assertionCache[$externalId])) {
            throw new SyncException(
                "No SAML assertion cached for NameID: {$externalId}. "
                . "Ensure the SAML callback populates the adapter before sync.",
                adapterName: $this->name(),
                externalId: $externalId,
            );
        }

        return $this->assertionCache[$externalId];
    }

    /**
     * Populate the assertion cache from a validated SAML response.
     *
     * Called by the SAML authentication callback after assertion validation.
     *
     * @param string                $nameId     The SAML NameID.
     * @param array<string, mixed>  $attributes All SAML attributes from the assertion.
     */
    public function loadAssertion(string $nameId, array $attributes): void
    {
        $roles = [];
        $rawRoles = $attributes[$this->roleAttribute] ?? [];

        if (is_array($rawRoles)) {
            foreach ($rawRoles as $role) {
                if (is_string($role) && $role !== '') {
                    $roles[] = $role;
                }
            }
        } elseif (is_string($rawRoles) && $rawRoles !== '') {
            $roles[] = $rawRoles;
        }

        $this->assertionCache[$nameId] = $roles;
    }

    /**
     * Clear cached assertion data (e.g., on logout).
     */
    public function clearAssertion(string $nameId): void
    {
        unset($this->assertionCache[$nameId]);
    }

    public function healthCheck(): bool
    {
        if ($this->metadataUrl === null) {
            // No metadata URL configured; assume healthy if adapter is instantiated
            return true;
        }

        // Attempt to fetch the IdP metadata XML
        $context = stream_context_create([
            'http' => ['timeout' => 5, 'method' => 'GET'],
            'ssl'  => ['verify_peer' => true],
        ]);

        $metadata = @file_get_contents($this->metadataUrl, false, $context);
        return $metadata !== false && str_contains($metadata, $this->idpEntityId);
    }

    public function roleMap(): array
    {
        return $this->roleMap;
    }
}
