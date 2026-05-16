<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Sync;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Backed enum defining how external roles are merged with local roles.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
enum SyncStrategy: string
{
    /**
     * Add external roles to the user without removing existing local roles.
     */
    case Additive = 'additive';

    /**
     * Replace all local roles with the external roles (full mirror).
     */
    case Replace = 'replace';

    /**
     * Merge: add missing external roles, remove roles not present in external source.
     * Identical to Replace but expressed semantically as a merge operation.
     */
    case Merge = 'merge';

    /**
     * Only sync roles that exist in the local database.
     * External roles with no local match are silently ignored.
     */
    case IntersectLocal = 'intersect_local';

    public function label(): string
    {
        return match ($this) {
            self::Additive      => 'Additive (append only)',
            self::Replace       => 'Replace (full mirror)',
            self::Merge         => 'Merge (add + remove)',
            self::IntersectLocal => 'Intersect (local-only)',
        };
    }
}
