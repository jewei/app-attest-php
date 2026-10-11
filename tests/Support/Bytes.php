<?php

declare(strict_types=1);

namespace AppAttest\Tests\Support;

/** A byte string for CborEncoder. Plain PHP strings encode as text strings. */
final readonly class Bytes
{
    public function __construct(public string $value) {}
}
