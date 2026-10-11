<?php

declare(strict_types=1);

namespace AppAttest\Internal;

use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;

/**
 * @internal A strict DER (X.690) reader for X.509 certificate extensions.
 *
 * It accepts single-byte tags and minimal definite lengths of up to four bytes
 * only. OpenSSL checks signatures, names, and validity; this class reads the
 * extensions that PHP's OpenSSL functions do not expose as bytes.
 */
final class Der
{
    public const int SEQUENCE = 0x30;

    public const int OCTET_STRING = 0x04;

    public const int OBJECT_IDENTIFIER = 0x06;

    public const int BOOLEAN = 0x01;

    /** The [3] EXPLICIT tag of TBSCertificate.extensions. */
    public const int EXTENSIONS = 0xA3;

    /**
     * Reads the element at $offset, which must end at or before $limit.
     *
     * @return array{tag: int, start: int, end: int} The tag, and the content's start and end offsets.
     */
    public static function element(string $data, int $offset, int $limit): array
    {
        if ($offset + 2 > $limit) {
            throw self::invalid('A DER element is truncated.');
        }

        $tag = ord($data[$offset]);

        if (($tag & 0x1F) === 0x1F) {
            throw self::invalid('A DER element has a multi-byte tag.');
        }

        $first = ord($data[$offset + 1]);
        $start = $offset + 2;

        if ($first < 0x80) {
            $length = $first;
        } else {
            $size = $first & 0x7F;

            if ($size === 0 || $size > 4 || $start + $size > $limit) {
                throw self::invalid('A DER element has an indefinite, oversized, or truncated length.');
            }

            if (ord($data[$start]) === 0) {
                throw self::invalid('A DER length is not minimal.');
            }

            $length = 0;

            for ($index = 0; $index < $size; $index++) {
                $length = ($length << 8) | ord($data[$start + $index]);
            }

            if ($length < 0x80) {
                throw self::invalid('A DER length is not minimal.');
            }

            $start += $size;
        }

        if ($length > $limit - $start) {
            throw self::invalid('A DER element is truncated.');
        }

        return ['tag' => $tag, 'start' => $start, 'end' => $start + $length];
    }

    /**
     * Reads the elements that exactly fill $start to $end.
     *
     * @return list<array{tag: int, start: int, end: int}>
     */
    public static function children(string $data, int $start, int $end): array
    {
        $children = [];

        for ($offset = $start; $offset < $end; $offset = $child['end']) {
            $child = self::element($data, $offset, $end);
            $children[] = $child;
        }

        return $children;
    }

    /**
     * Returns the extensions of a DER certificate, keyed by the OID's content bytes.
     *
     * The certificate must be one SEQUENCE that fills $certificate. An OID that
     * appears twice is refused (RFC 5280, section 4.2).
     *
     * @return array<string, array{critical: bool, value: string}>
     */
    public static function extensions(string $certificate): array
    {
        $outer = self::element($certificate, 0, strlen($certificate));

        if ($outer['tag'] !== self::SEQUENCE || $outer['end'] !== strlen($certificate)) {
            throw self::invalid('A certificate is not one DER SEQUENCE.');
        }

        $parts = self::children($certificate, $outer['start'], $outer['end']);

        if (count($parts) !== 3 || $parts[0]['tag'] !== self::SEQUENCE) {
            throw self::invalid('A certificate does not have a TBSCertificate, an algorithm, and a signature.');
        }

        $wrapper = null;

        foreach (self::children($certificate, $parts[0]['start'], $parts[0]['end']) as $field) {
            if ($field['tag'] === self::EXTENSIONS) {
                if ($wrapper !== null) {
                    throw self::invalid('A certificate has two extension lists.');
                }

                $wrapper = $field;
            }
        }

        if ($wrapper === null) {
            return [];
        }

        $list = self::children($certificate, $wrapper['start'], $wrapper['end']);

        if (count($list) !== 1 || $list[0]['tag'] !== self::SEQUENCE) {
            throw self::invalid('The certificate extensions are not one SEQUENCE.');
        }

        $extensions = [];

        foreach (self::children($certificate, $list[0]['start'], $list[0]['end']) as $extension) {
            if ($extension['tag'] !== self::SEQUENCE) {
                throw self::invalid('A certificate extension is not a SEQUENCE.');
            }

            $fields = self::children($certificate, $extension['start'], $extension['end']);
            $critical = false;

            if (count($fields) === 3 && $fields[1]['tag'] === self::BOOLEAN && $fields[1]['end'] - $fields[1]['start'] === 1) {
                $critical = ord($certificate[$fields[1]['start']]) !== 0;
                $fields = [$fields[0], $fields[2]];
            }

            if (count($fields) !== 2 || $fields[0]['tag'] !== self::OBJECT_IDENTIFIER || $fields[1]['tag'] !== self::OCTET_STRING) {
                throw self::invalid('A certificate extension does not have an OID, an optional critical flag, and a value.');
            }

            $oid = self::content($certificate, $fields[0]);

            if (array_key_exists($oid, $extensions)) {
                throw self::invalid('A certificate has the same extension twice.');
            }

            $extensions[$oid] = ['critical' => $critical, 'value' => self::content($certificate, $fields[1])];
        }

        return $extensions;
    }

    /**
     * Returns the octet string in the App Attest nonce extension value:
     * SEQUENCE { [1] EXPLICIT OCTET STRING }.
     */
    public static function nonce(string $value): string
    {
        $sequence = self::element($value, 0, strlen($value));

        if ($sequence['tag'] !== self::SEQUENCE || $sequence['end'] !== strlen($value)) {
            throw self::invalid('The nonce extension is not one SEQUENCE.');
        }

        $tagged = self::children($value, $sequence['start'], $sequence['end']);

        if (count($tagged) !== 1 || $tagged[0]['tag'] !== 0xA1) {
            throw self::invalid('The nonce extension does not contain one [1] element.');
        }

        $octets = self::children($value, $tagged[0]['start'], $tagged[0]['end']);

        if (count($octets) !== 1 || $octets[0]['tag'] !== self::OCTET_STRING) {
            throw self::invalid('The nonce extension does not contain one OCTET STRING.');
        }

        return self::content($value, $octets[0]);
    }

    /** @param array{tag: int, start: int, end: int} $element */
    private static function content(string $data, array $element): string
    {
        return substr($data, $element['start'], $element['end'] - $element['start']);
    }

    private static function invalid(string $message): VerificationException
    {
        return VerificationException::because(Failure::InvalidCertificate, $message);
    }
}
