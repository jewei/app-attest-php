<?php

declare(strict_types=1);

namespace AppAttest\Tests\Support;

/** A CBOR map for CborEncoder, for maps that PHP would see as lists, such as {0: a, 1: b} or {}. */
final readonly class Map
{
    /** @param array<int|string, mixed> $entries */
    public function __construct(public array $entries) {}
}
