<?php

declare(strict_types=1);

namespace AppAttest\Internal;

use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;

/**
 * @internal A strict decoder for the CBOR (RFC 8949) subset that App Attest uses.
 *
 * It accepts unsigned and negative integers, byte strings, UTF-8 text strings,
 * arrays, maps, false, true, and null, all with definite lengths, so that an
 * unknown extension with such values does not refuse every key. An extension
 * with a tag or a float would refuse every key; Apple uses neither (accepted
 * risk: it fails closed). It refuses tags, floats, other simple values,
 * indefinite lengths, integers outside the 64-bit PHP int range,
 * duplicate or non-scalar map keys, deep nesting, and large containers. Each
 * length is checked against the remaining input before any data is read.
 *
 * It accepts a length or integer in a longer form than needed (RFC 8949,
 * section 4.2.1, "preferred serialization" is not required): the value is the
 * same, and App Attest signs authenticator data as raw bytes, not the CBOR
 * around it.
 *
 * Results: int, string (text), ByteString, list<mixed> (array), CborMap, bool, and null.
 * PHP turns a text key such as "1" into the int key 1; such a key and the
 * integer 1 count as duplicates.
 */
final class Cbor
{
    public const int MAX_DEPTH = 8;

    public const int MAX_ITEMS = 64;

    /** Decodes one item that must fill the whole input. */
    public static function decode(string $data): mixed
    {
        $offset = 0;
        $value = self::item($data, $offset, 1);

        if ($offset !== strlen($data)) {
            throw self::malformed('The CBOR data has bytes after the first item.');
        }

        return $value;
    }

    /**
     * Decodes one item at $offset and returns it with the offset after it.
     *
     * @return array{mixed, int}
     */
    public static function decodePrefix(string $data, int $offset): array
    {
        if ($offset < 0 || $offset > strlen($data)) {
            throw self::malformed('The CBOR offset is outside the data.');
        }

        $value = self::item($data, $offset, 1);

        return [$value, $offset];
    }

    private static function item(string $data, int &$offset, int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            throw self::malformed('The CBOR data is nested too deeply.');
        }

        $initial = ord(self::take($data, $offset, 1));
        $major = $initial >> 5;

        // false, true, and null; every other major type 7 value (floats, other simple values, break) is refused.
        if ($major === 7) {
            return match ($initial) {
                0xF4 => false,
                0xF5 => true,
                0xF6 => null,
                default => throw self::malformed('The CBOR data has a float or an unsupported simple value.'),
            };
        }

        $argument = self::argument($data, $offset, $initial & 0x1F);

        return match ($major) {
            0 => $argument,
            1 => -1 - $argument,
            2 => new ByteString(self::take($data, $offset, $argument)),
            3 => self::text(self::take($data, $offset, $argument)),
            4 => self::sequence($data, $offset, $argument, $depth),
            5 => self::map($data, $offset, $argument, $depth),
            default => throw self::malformed('The CBOR data has a tag.'),
        };
    }

    private static function argument(string $data, int &$offset, int $info): int
    {
        if ($info < 24) {
            return $info;
        }

        $size = match ($info) {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            default => throw self::malformed('The CBOR data has an indefinite or reserved length.'),
        };

        $bytes = self::take($data, $offset, $size);

        if ($size === 8 && ord($bytes[0]) > 0x7F) {
            throw self::malformed('The CBOR integer is outside the PHP int range.');
        }

        $value = 0;

        foreach (str_split($bytes) as $byte) {
            $value = ($value << 8) | ord($byte);
        }

        return $value;
    }

    private static function take(string $data, int &$offset, int $length): string
    {
        if ($length > strlen($data) - $offset) {
            throw self::malformed('The CBOR data is truncated.');
        }

        $bytes = substr($data, $offset, $length);
        $offset += $length;

        return $bytes;
    }

    private static function text(string $bytes): string
    {
        if (preg_match('//u', $bytes) !== 1) {
            throw self::malformed('A CBOR text string is not valid UTF-8.');
        }

        return $bytes;
    }

    /** @return list<mixed> */
    private static function sequence(string $data, int &$offset, int $count, int $depth): array
    {
        self::checkCount($count);
        $items = [];

        for ($index = 0; $index < $count; $index++) {
            $items[] = self::item($data, $offset, $depth + 1);
        }

        return $items;
    }

    private static function map(string $data, int &$offset, int $count, int $depth): CborMap
    {
        self::checkCount($count);
        $map = [];

        for ($index = 0; $index < $count; $index++) {
            // Defensive: a key that is a container is refused below anyway; the depth only bounds its decoding.
            $key = self::item($data, $offset, $depth + 1);

            if (! is_int($key) && ! is_string($key)) {
                throw self::malformed('A CBOR map key is not an integer or a text string.');
            }

            if (array_key_exists($key, $map)) {
                throw self::malformed('A CBOR map has a duplicate key.');
            }

            $map[$key] = self::item($data, $offset, $depth + 1);
        }

        return new CborMap($map);
    }

    private static function checkCount(int $count): void
    {
        if ($count > self::MAX_ITEMS) {
            throw self::malformed('A CBOR array or map has too many entries.');
        }
    }

    private static function malformed(string $message): VerificationException
    {
        return VerificationException::because(Failure::MalformedInput, $message);
    }
}
