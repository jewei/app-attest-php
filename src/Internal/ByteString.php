<?php

declare(strict_types=1);

namespace AppAttest\Internal;

/**
 * @internal A CBOR byte string. Text strings decode to PHP strings, so byte
 * strings need their own type.
 */
final readonly class ByteString
{
    public function __construct(public string $value) {}
}
