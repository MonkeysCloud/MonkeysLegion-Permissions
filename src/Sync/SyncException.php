<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Sync;

use RuntimeException;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Exception thrown when a sync adapter encounters a communication or data error.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class SyncException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly string $adapterName = '',
        public readonly ?string $externalId = null,
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }
}
