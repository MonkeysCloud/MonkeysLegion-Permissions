<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Exceptions;

use RuntimeException;
use MonkeysLegion\Permissions\Decision;

/**
 * Thrown when an identity lacks the required permission or role.
 */
class AuthorizationException extends RuntimeException
{
    public function __construct(
        string $message = 'This action is unauthorized.',
        public readonly ?Decision $decision = null,
    ) {
        parent::__construct($message, 403);
    }
}
