<?php

declare(strict_types=1);

namespace AppAttest\Internal;

use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;

/**
 * @internal A strict DER (X.690) reader for X.509 certificates (RFC 5280).
 *
 * It accepts single-byte tags and minimal definite lengths of up to four bytes
 * only. It reads the fields that the chain check needs: the issuer and subject
 * names as DER bytes, the validity period, and the extensions. OpenSSL checks
 * the signatures.
 *
 * @phpstan-type Element array{tag: int, offset: int, start: int, end: int}
 * @phpstan-type Extension array{oid: string, critical: bool, value: string}
 */
final class Der
{
    public const int BOOLEAN = 0x01;

    public const int INTEGER = 0x02;

    public const int BIT_STRING = 0x03;

    public const int OCTET_STRING = 0x04;

    public const int OBJECT_IDENTIFIER = 0x06;

    public const int UTC_TIME = 0x17;

    public const int GENERALIZED_TIME = 0x18;

    public const int SEQUENCE = 0x30;

    /** OID 2.5.29.19, basicConstraints, as DER content bytes. */
    public const string BASIC_CONSTRAINTS = "\x55\x1D\x13";

    /** OID 2.5.29.15, keyUsage, as DER content bytes. */
    public const string KEY_USAGE = "\x55\x1D\x0F";

    /**
     * Reads the element at $offset, which must end at or before $limit.
     *
     * @return Element The tag, the header offset, and the content's start and end offsets.
     */
    public static function element(string $data, int $offset, int $limit): array
    {
        if ($offset < 0 || $limit > strlen($data) || $offset + 2 > $limit) {
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

        return ['tag' => $tag, 'offset' => $offset, 'start' => $start, 'end' => $start + $length];
    }

    /**
     * Reads the elements that exactly fill $start to $end.
     *
     * @return list<Element>
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
     * Reads a version 3 DER certificate that fills $certificate.
     *
     * Extensions are a list in certificate order; an OID that appears twice
     * is refused (RFC 5280, section 4.2).
     *
     * @return array{issuer: string, subject: string, notBefore: int, notAfter: int, extensions: list<Extension>}
     */
    public static function certificate(string $certificate): array
    {
        $outer = self::whole($certificate, self::SEQUENCE, 'A certificate');
        $parts = self::children($certificate, $outer['start'], $outer['end']);

        if (count($parts) !== 3 || $parts[0]['tag'] !== self::SEQUENCE || $parts[1]['tag'] !== self::SEQUENCE || $parts[2]['tag'] !== self::BIT_STRING) {
            throw self::invalid('A certificate does not have a TBSCertificate, an algorithm, and a signature.');
        }

        // TBSCertificate: [0] version, serialNumber, signature, issuer, validity, subject,
        // subjectPublicKeyInfo, then optional [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions.
        $fields = self::children($certificate, $parts[0]['start'], $parts[0]['end']);
        $tags = array_map(static fn (array $field): int => $field['tag'], $fields);

        if (array_slice($tags, 0, 7) !== [0xA0, self::INTEGER, self::SEQUENCE, self::SEQUENCE, self::SEQUENCE, self::SEQUENCE, self::SEQUENCE]) {
            throw self::invalid('A certificate does not have the version 3 TBSCertificate fields.');
        }

        if (! in_array(array_slice($tags, 7), [[], [0xA3], [0x81, 0xA3], [0x82, 0xA3], [0x81, 0x82, 0xA3], [0x81], [0x82], [0x81, 0x82]], true)) {
            throw self::invalid('A certificate has unexpected fields after the public key.');
        }

        $validity = self::children($certificate, $fields[4]['start'], $fields[4]['end']);

        if (count($validity) !== 2) {
            throw self::invalid('A certificate validity does not have two times.');
        }

        $last = $fields[count($fields) - 1];

        return [
            'issuer' => self::raw($certificate, $fields[3]),
            'subject' => self::raw($certificate, $fields[5]),
            'notBefore' => self::time($certificate, $validity[0]),
            'notAfter' => self::time($certificate, $validity[1]),
            'extensions' => $last['tag'] === 0xA3 ? self::extensions($certificate, $last) : [],
        ];
    }

    /**
     * Returns the value of the extension with $oid, or null.
     *
     * @param  list<Extension>  $extensions
     */
    public static function extensionValue(array $extensions, string $oid): ?string
    {
        foreach ($extensions as $extension) {
            if ($extension['oid'] === $oid) {
                return $extension['value'];
            }
        }

        return null;
    }

    /**
     * Decodes a basicConstraints value: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }.
     *
     * @return array{ca: bool, pathLength: ?int}
     */
    public static function basicConstraints(string $value): array
    {
        $sequence = self::whole($value, self::SEQUENCE, 'basicConstraints');
        $fields = self::children($value, $sequence['start'], $sequence['end']);
        $ca = false;
        $pathLength = null;

        if ($fields !== [] && $fields[0]['tag'] === self::BOOLEAN) {
            $ca = self::boolean($value, $fields[0]);
            $fields = array_slice($fields, 1);
        }

        if ($fields !== [] && $fields[0]['tag'] === self::INTEGER) {
            $pathLength = self::smallInteger($value, $fields[0]);
            $fields = array_slice($fields, 1);
        }

        if ($fields !== []) {
            throw self::invalid('basicConstraints has unexpected fields.');
        }

        return ['ca' => $ca, 'pathLength' => $pathLength];
    }

    /** Decodes a keyUsage BIT STRING and reports whether keyCertSign (bit 5) is set. */
    public static function allowsCertificateSigning(string $value): bool
    {
        $bits = self::whole($value, self::BIT_STRING, 'keyUsage');

        if ($bits['end'] - $bits['start'] < 2 || ord($value[$bits['start']]) > 7) {
            throw self::invalid('keyUsage is not a non-empty BIT STRING.');
        }

        return (ord($value[$bits['start'] + 1]) & 0x04) !== 0;
    }

    /**
     * Returns the octet string in the App Attest nonce extension value:
     * SEQUENCE { [1] EXPLICIT OCTET STRING }.
     */
    public static function nonce(string $value): string
    {
        $sequence = self::whole($value, self::SEQUENCE, 'The nonce extension');
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

    /**
     * @param  Element  $wrapper  The [3] element.
     * @return list<Extension>
     */
    private static function extensions(string $certificate, array $wrapper): array
    {
        $list = self::children($certificate, $wrapper['start'], $wrapper['end']);

        if (count($list) !== 1 || $list[0]['tag'] !== self::SEQUENCE) {
            throw self::invalid('The certificate extensions are not one SEQUENCE.');
        }

        $extensions = [];
        $seen = [];

        foreach (self::children($certificate, $list[0]['start'], $list[0]['end']) as $extension) {
            if ($extension['tag'] !== self::SEQUENCE) {
                throw self::invalid('A certificate extension is not a SEQUENCE.');
            }

            $fields = self::children($certificate, $extension['start'], $extension['end']);
            $critical = false;

            if (count($fields) === 3 && $fields[1]['tag'] === self::BOOLEAN) {
                $critical = self::boolean($certificate, $fields[1]);
                $fields = [$fields[0], $fields[2]];
            }

            if (count($fields) !== 2 || $fields[0]['tag'] !== self::OBJECT_IDENTIFIER || $fields[1]['tag'] !== self::OCTET_STRING) {
                throw self::invalid('A certificate extension does not have an OID, an optional critical flag, and a value.');
            }

            $oid = self::content($certificate, $fields[0]);

            // The prefix keeps PHP from turning an OID such as "123" into an integer key.
            if (isset($seen['oid:'.$oid])) {
                throw self::invalid('A certificate has the same extension twice.');
            }

            $seen['oid:'.$oid] = true;
            $extensions[] = ['oid' => $oid, 'critical' => $critical, 'value' => self::content($certificate, $fields[1])];
        }

        return $extensions;
    }

    /**
     * Reads a validity time in the only forms that RFC 5280 (section 4.1.2.5) allows:
     * UTCTime YYMMDDHHMMSSZ and GeneralizedTime YYYYMMDDHHMMSSZ, both in UTC.
     *
     * @param  Element  $element
     */
    private static function time(string $data, array $element): int
    {
        $pattern = match ($element['tag']) {
            self::UTC_TIME => '/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/D',
            self::GENERALIZED_TIME => '/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/D',
            default => throw self::invalid('A certificate time is not a UTCTime or a GeneralizedTime.'),
        };

        if (preg_match($pattern, self::content($data, $element), $parts) !== 1) {
            throw self::invalid('A certificate time is not in the form YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ.');
        }

        [$year, $month, $day, $hour, $minute, $second] = array_map(intval(...), array_slice($parts, 1));

        if ($element['tag'] === self::UTC_TIME) {
            $year += $year >= 50 ? 1900 : 2000;
        }

        if (! checkdate($month, $day, $year) || $hour > 23 || $minute > 59 || $second > 59) {
            throw self::invalid('A certificate time is not a valid date and time.');
        }

        $timestamp = gmmktime($hour, $minute, $second, $month, $day, $year);

        return $timestamp !== false ? $timestamp : throw self::invalid('A certificate time is out of range.');
    }

    /** @param Element $element */
    private static function boolean(string $data, array $element): bool
    {
        $content = self::content($data, $element);

        if ($content !== "\x00" && $content !== "\xFF") {
            throw self::invalid('A DER BOOLEAN is not 0x00 or 0xFF.');
        }

        return $content === "\xFF";
    }

    /**
     * Reads a non-negative INTEGER of at most two content bytes.
     *
     * @param  Element  $element
     */
    private static function smallInteger(string $data, array $element): int
    {
        $content = self::content($data, $element);
        $length = strlen($content);

        if ($length === 0 || $length > 2 || ord($content[0]) > 0x7F || ($length === 2 && ord($content[0]) === 0 && ord($content[1]) < 0x80)) {
            throw self::invalid('A DER INTEGER is negative, too large, or not minimal.');
        }

        return $length === 1 ? ord($content[0]) : (ord($content[0]) << 8) | ord($content[1]);
    }

    /** @return Element */
    private static function whole(string $value, int $tag, string $name): array
    {
        $element = self::element($value, 0, strlen($value));

        if ($element['tag'] !== $tag || $element['end'] !== strlen($value)) {
            throw self::invalid("{$name} is not one DER element of the expected type.");
        }

        return $element;
    }

    /** @param Element $element */
    private static function content(string $data, array $element): string
    {
        return substr($data, $element['start'], $element['end'] - $element['start']);
    }

    /**
     * The whole element, with its tag and length.
     *
     * @param  Element  $element
     */
    private static function raw(string $data, array $element): string
    {
        return substr($data, $element['offset'], $element['end'] - $element['offset']);
    }

    private static function invalid(string $message): VerificationException
    {
        return VerificationException::because(Failure::InvalidCertificate, $message);
    }
}
