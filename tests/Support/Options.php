<?php

declare(strict_types=1);

namespace AppAttest\Tests\Support;

use Closure;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;

/** Reads typed test options and refuses a value of the wrong type. */
final class Options
{
    /** @param array<mixed> $options */
    public static function int(array $options, string $name, int $default): int
    {
        $value = $options[$name] ?? $default;

        return is_int($value) ? $value : throw self::wrong($name, 'an int');
    }

    /** @param array<mixed> $options */
    public static function string(array $options, string $name, string $default): string
    {
        $value = $options[$name] ?? $default;

        return is_string($value) ? $value : throw self::wrong($name, 'a string');
    }

    /**
     * Returns $default when the option is absent, and null when it is null.
     *
     * @param  array<mixed>  $options
     */
    public static function nullableString(array $options, string $name, ?string $default): ?string
    {
        $value = array_key_exists($name, $options) ? $options[$name] : $default;

        return $value === null || is_string($value) ? $value : throw self::wrong($name, 'a string or null');
    }

    /** @param array<mixed> $options */
    public static function key(array $options, string $name): ?OpenSSLAsymmetricKey
    {
        $value = $options[$name] ?? null;

        return $value === null || $value instanceof OpenSSLAsymmetricKey ? $value : throw self::wrong($name, 'a key');
    }

    /** @param array<mixed> $options */
    public static function closure(array $options, string $name): ?Closure
    {
        $value = $options[$name] ?? null;

        return $value === null || $value instanceof Closure ? $value : throw self::wrong($name, 'a closure');
    }

    private static function wrong(string $name, string $type): InvalidArgumentException
    {
        return new InvalidArgumentException("The test option {$name} must be {$type}.");
    }
}
