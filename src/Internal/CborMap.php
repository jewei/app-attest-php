<?php

declare(strict_types=1);

namespace AppAttest\Internal;

/**
 * @internal A decoded CBOR map. Arrays decode to PHP lists, so maps need their
 * own type: a map with the keys 0 and 1 is not an array.
 */
final readonly class CborMap
{
    /** @param array<int|string, mixed> $entries */
    public function __construct(public array $entries) {}

    public function get(int|string $key): mixed
    {
        return $this->entries[$key] ?? null;
    }

    /**
     * True when the map has exactly these keys.
     *
     * @param  list<int|string>  $keys
     */
    public function hasExactly(array $keys): bool
    {
        if (count($this->entries) !== count($keys)) {
            return false;
        }

        foreach ($keys as $key) {
            if (! array_key_exists($key, $this->entries)) {
                return false;
            }
        }

        return true;
    }
}
