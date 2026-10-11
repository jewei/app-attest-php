<?php

declare(strict_types=1);

namespace AppAttest\Exception;

use RuntimeException;

/**
 * Data from the device failed a check. Catch this; do not construct it.
 *
 * Arguments that come from your server, such as a stored public key, throw
 * InvalidArgumentException instead.
 */
final class VerificationException extends RuntimeException
{
    private function __construct(public readonly Failure $failure, string $message)
    {
        parent::__construct($message);
    }

    /** @internal */
    public static function because(Failure $failure, string $message): self
    {
        return new self($failure, $message);
    }
}
