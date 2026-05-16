<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Event;

use MonkeysLegion\Events\Event;
use MonkeysLegion\Permissions\Sync\SyncResult;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Dispatched after a role sync operation completes.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class RolesSynced extends Event
{
    public function __construct(
        public readonly SyncResult $result,
    ) {
        parent::__construct();
    }
}
