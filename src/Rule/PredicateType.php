<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Rule;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Backed enum representing predicate types for the composable Rule engine.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
enum PredicateType: string
{
    case UserHas         = 'user_has';
    case UserAttribute   = 'user_attribute';
    case ResourceAttr    = 'resource_attribute';
    case TimeOfDay       = 'time_of_day';
    case DayOfWeek       = 'day_of_week';
    case IpRange         = 'ip_range';
    case TenantIs        = 'tenant_is';
    case Callback        = 'callback';
    case All             = 'all';
    case Any             = 'any';
    case Not             = 'not';

    /**
     * Whether this predicate type is a composite (contains children).
     */
    public function isComposite(): bool
    {
        return match ($this) {
            self::All, self::Any, self::Not => true,
            default => false,
        };
    }
}
