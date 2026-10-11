<?php

declare(strict_types=1);

namespace AppAttest\Tests\Support;

use InvalidArgumentException;

/** Encodes test data as CBOR with shortest-form lengths. Lists become arrays; other arrays become maps. */
final class CborEncoder
{
    public static function encode(mixed $value): string
    {
        return match (true) {
            is_int($value) && $value >= 0 => self::head(0, $value),
            is_int($value) => self::head(1, -1 - $value),
            $value instanceof Bytes => self::head(2, strlen($value->value)).$value->value,
            is_string($value) => self::head(3, strlen($value)).$value,
            is_array($value) && array_is_list($value) => self::head(4, count($value)).implode('', array_map(self::encode(...), $value)),
            is_array($value) => self::head(5, count($value)).implode('', array_map(
                static fn (int|string $key, mixed $item): string => self::encode($key).self::encode($item),
                array_keys($value),
                $value,
            )),
            default => throw new InvalidArgumentException('CborEncoder cannot encode this value.'),
        };
    }

    public static function head(int $major, int $argument): string
    {
        $type = $major << 5;

        return match (true) {
            $argument < 24 => chr($type | $argument),
            $argument <= 0xFF => chr($type | 24).chr($argument),
            $argument <= 0xFFFF => chr($type | 25).pack('n', $argument),
            $argument <= 0xFFFFFFFF => chr($type | 26).pack('N', $argument),
            default => chr($type | 27).pack('J', $argument),
        };
    }
}
