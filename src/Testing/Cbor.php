<?php

declare(strict_types=1);

namespace AppAttest\Testing;

/** @internal A minimal CBOR encoder for test devices. Values are encoded already. */
final class Cbor
{
    /** @param array<int|string, string|int> $entries Keys are encoded as integers or text; values are encoded CBOR or integers. */
    public static function map(array $entries): string
    {
        $encoded = self::head(5, count($entries));

        foreach ($entries as $key => $value) {
            $encoded .= (is_int($key) ? self::integer($key) : self::text($key)).(is_int($value) ? self::integer($value) : $value);
        }

        return $encoded;
    }

    /** @param list<string> $items Encoded CBOR items. */
    public static function array(array $items): string
    {
        return self::head(4, count($items)).implode('', $items);
    }

    public static function bytes(string $value): string
    {
        return self::head(2, strlen($value)).$value;
    }

    public static function text(string $value): string
    {
        return self::head(3, strlen($value)).$value;
    }

    public static function integer(int $value): string
    {
        return $value >= 0 ? self::head(0, $value) : self::head(1, -1 - $value);
    }

    private static function head(int $major, int $argument): string
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
