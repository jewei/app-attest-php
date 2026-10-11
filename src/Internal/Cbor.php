<?php

declare(strict_types=1);

namespace AppAttest\Internal;

use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;

/**
 * @internal A strict decoder for the CBOR (RFC 8949) subset that App Attest uses.
 *
 * It accepts unsigned and negative integers, byte strings, UTF-8 text strings,
 * arrays, and maps, all with definite lengths. It refuses tags, floats, simple
 * values, indefinite lengths, integers outside the PHP int range, duplicate or
 * non-scalar map keys, deep nesting, and large containers. Each length is
 * checked against the remaining input before any data is read.
 *
 * Results: int, string (text), ByteString, list<mixed> (array), and
 * array<int|string, mixed> (map). PHP turns a text key such as "1" into the
 * int key 1; such a key and the integer 1 count as duplicates.
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
        $argument = self::argument($data, $offset, $initial & 0x1F);

        return match ($major) {
            0 => $argument,
            1 => -1 - $argument,
            2 => new ByteString(self::take($data, $offset, $argument)),
            3 => self::text(self::take($data, $offset, $argument)),
            4 => self::sequence($data, $offset, $argument, $depth),
            5 => self::map($data, $offset, $argument, $depth),
            default => throw self::malformed('The CBOR data has a tag, a float, or a simple value.'),
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
        self::checkCount($data, $offset, $count);
        $items = [];

        for ($index = 0; $index < $count; $index++) {
            $items[] = self::item($data, $offset, $depth + 1);
        }

        return $items;
    }

    /** @return array<int|string, mixed> */
    private static function map(string $data, int &$offset, int $count, int $depth): array
    {
        self::checkCount($data, $offset, $count);
        $map = [];

        for ($index = 0; $index < $count; $index++) {
            $key = self::item($data, $offset, $depth + 1);

            if (! is_int($key) && ! is_string($key)) {
                throw self::malformed('A CBOR map key is not an integer or a text string.');
            }

            if (array_key_exists($key, $map)) {
                throw self::malformed('A CBOR map has a duplicate key.');
            }

            $map[$key] = self::item($data, $offset, $depth + 1);
        }

        return $map;
    }

    /** Each entry needs at least one byte, so a count above the remaining bytes is truncated data. */
    private static function checkCount(string $data, int $offset, int $count): void
    {
        if ($count > self::MAX_ITEMS || $count > strlen($data) - $offset) {
            throw self::malformed('A CBOR array or map has too many entries.');
        }
    }

    private static function malformed(string $message): VerificationException
    {
        return VerificationException::because(Failure::MalformedInput, $message);
    }
}
