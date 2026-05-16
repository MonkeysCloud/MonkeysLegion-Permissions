<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Entity;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Backed enum for the type of permission being requested.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
enum RequestType: string
{
    case Permission = 'permission';
    case Role       = 'role';
}
