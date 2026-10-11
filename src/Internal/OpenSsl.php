<?php

declare(strict_types=1);

namespace AppAttest\Internal;

use Closure;

/**
 * @internal Runs PHP OpenSSL calls on untrusted input.
 *
 * Some calls, such as openssl_x509_read(), emit a PHP warning for bad input.
 * The verifier reports bad input with VerificationException instead, so this
 * class mutes those warnings during the call. It also empties OpenSSL's error
 * queue, so later openssl_error_string() calls in the application do not see
 * this package's errors. The queue is per process and OpenSSL cannot put
 * entries back, so errors that the application left in the queue before the
 * call are removed too.
 */
final class OpenSsl
{
    /**
     * @template T
     *
     * @param  Closure(): T  $call
     * @return T
     */
    public static function quietly(Closure $call): mixed
    {
        set_error_handler(static fn (): bool => true);

        try {
            return $call();
        } finally {
            restore_error_handler();
            self::clearErrors();
        }
    }

    public static function clearErrors(): void
    {
        while (openssl_error_string() !== false) {
            // Each call removes one message from the queue.
        }
    }
}
