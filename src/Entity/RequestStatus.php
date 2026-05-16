<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Entity;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Backed enum representing the lifecycle state of a PermissionRequest.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
enum RequestStatus: string
{
    case Pending  = 'pending';
    case Approved = 'approved';
    case Denied   = 'denied';
    case Expired  = 'expired';
    case Revoked  = 'revoked';

    public function isFinal(): bool
    {
        return match ($this) {
            self::Approved, self::Denied, self::Expired, self::Revoked => true,
            self::Pending => false,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Pending  => 'Pending Review',
            self::Approved => 'Approved',
            self::Denied   => 'Denied',
            self::Expired  => 'Expired',
            self::Revoked  => 'Revoked',
        };
    }
}
