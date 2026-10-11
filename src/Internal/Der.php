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
 * names as DER bytes, the validity period, the public key and its curve, and
 * the extensions. OpenSSL checks the signatures.
 *
 * @phpstan-type Element array{tag: int, offset: int, start: int, end: int}
 * @phpstan-type Extension array{oid: string, critical: bool, value: string}
 * @phpstan-type Certificate array{issuer: string, subject: string, publicKey: string, curve: ?string, notBefore: int, notAfter: int, extensions: list<Extension>}
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

    /** OID 1.2.840.10045.2.1, id-ecPublicKey. */
    public const string EC_PUBLIC_KEY = "\x2A\x86\x48\xCE\x3D\x02\x01";

    /** OID 1.2.840.10045.3.1.7, prime256v1 (P-256). */
    public const string P256 = "\x2A\x86\x48\xCE\x3D\x03\x01\x07";

    /** OID 1.3.132.0.34, secp384r1 (P-384). */
    public const string P384 = "\x2B\x81\x04\x00\x22";

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

        [$start, $end] = self::length($data, $offset + 1, $limit);

        return ['tag' => $tag, 'offset' => $offset, 'start' => $start, 'end' => $end];
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
     * `publicKey` is the SubjectPublicKeyInfo DER. `curve` is the named curve OID (content bytes) of an
     * id-ecPublicKey key, or null for any other key.
     *
     * @return array{issuer: string, subject: string, publicKey: string, curve: ?string, notBefore: int, notAfter: int, extensions: list<Extension>}
     */
    public static function certificate(string $certificate): array
    {
        $outer = self::whole($certificate, self::SEQUENCE, 'A certificate');
        $parts = self::children($certificate, $outer['start'], $outer['end']);

        // The tag of $parts[1] is defensive: certificate() compares the algorithm with the signed one byte for byte.
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

        if (self::raw($certificate, $fields[0]) !== "\xA0\x03\x02\x01\x02") {
            throw self::invalid('A certificate is not version 3.');
        }

        // RFC 5280, section 4.1.1.2: the outer algorithm, which the signature does not cover, equals the signed one.
        if (self::raw($certificate, $parts[1]) !== self::raw($certificate, $fields[2])) {
            throw self::invalid('A certificate\'s signature algorithm differs from its signed algorithm.');
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
            'publicKey' => self::raw($certificate, $fields[6]),
            'curve' => self::curve($certificate, $fields[6]),
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
            // DER omits the DEFAULT FALSE, so a written cA is TRUE.
            if (! self::boolean($value, $fields[0])) {
                throw self::invalid('basicConstraints writes the default cA FALSE.');
            }

            $ca = true;
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

        $unused = $bits['end'] - $bits['start'] < 2 ? 8 : ord($value[$bits['start']]);

        if ($unused > 7) {
            throw self::invalid('keyUsage is not a non-empty BIT STRING.');
        }

        $last = ord($value[$bits['end'] - 1]);

        // DER sets the unused bits to zero (X.690, section 11.2.1) and removes trailing zero named bits
        // (section 11.2.2), so the last named bit is set.
        if (($last & ((1 << $unused) - 1)) !== 0 || (($last >> $unused) & 1) !== 1) {
            throw self::invalid('keyUsage is not minimal DER: unused bits are set or named bits trail as zeros.');
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
     * Returns the text of the platform field ([1026], for example "iphoneos") in the App Attest extension
     * 1.2.840.113635.100.8.7, or null when the field is absent. The extension is a SEQUENCE of context-specific
     * fields, many with multi-byte tag numbers, which element() refuses elsewhere. Other context-specific fields are
     * skipped; a field of another class is refused.
     */
    public static function platform(string $value): ?string
    {
        $sequence = self::whole($value, self::SEQUENCE, 'The App Attest platform extension');
        $fields = [];

        for ($offset = $sequence['start']; $offset < $sequence['end']; $offset = $end) {
            $tag = ord($value[$offset]);

            // Apple writes context-specific fields; one of another class means the format changed, so it is refused.
            // Context-specific fields other than [1026] are skipped.
            if (($tag & 0xC0) !== 0x80) {
                throw self::invalid('A field of the platform extension is not context-specific.');
            }

            $offset++;
            $number = $tag & 0x1F;

            if ($number === 0x1F) {
                $number = 0;

                for ($index = 0; ; $index++) {
                    if ($index === 4 || $offset >= $sequence['end'] || ($index === 0 && ord($value[$offset]) === 0x80)) {
                        throw self::invalid('A field of the platform extension has an invalid tag number.');
                    }

                    $byte = ord($value[$offset++]);
                    $number = ($number << 7) | ($byte & 0x7F);

                    if ($byte < 0x80) {
                        break;
                    }
                }

                // X.690, section 8.1.2.2: numbers below 31 have the one-byte form.
                if ($number < 31) {
                    throw self::invalid('A field of the platform extension writes a small tag number in the long form.');
                }
            }

            [$start, $end] = self::length($value, $offset, $sequence['end']);

            if (isset($fields[$number])) {
                throw self::invalid('The platform extension has the same field twice.');
            }

            $fields[$number] = ['constructed' => ($tag & 0x20) !== 0, 'content' => substr($value, $start, $end - $start)];
        }

        if (! isset($fields[1026])) {
            return null;
        }

        if (! $fields[1026]['constructed']) {
            throw self::invalid('The platform field is not an explicitly tagged value.');
        }

        $text = self::whole($fields[1026]['content'], self::OCTET_STRING, 'The platform field');

        return self::content($fields[1026]['content'], $text);
    }

    /**
     * Reads the length at $offset and returns the content's start and end offsets.
     *
     * @return array{int, int}
     */
    private static function length(string $data, int $offset, int $limit): array
    {
        if ($offset >= $limit) {
            throw self::invalid('A DER length is missing.');
        }

        $first = ord($data[$offset]);
        $start = $offset + 1;

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

        return [$start, $start + $length];
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
        $entries = self::children($certificate, $list[0]['start'], $list[0]['end']);

        if ($entries === []) {
            throw self::invalid('The certificate extension list is empty (RFC 5280 requires at least one).');
        }

        foreach ($entries as $extension) {
            if ($extension['tag'] !== self::SEQUENCE) {
                throw self::invalid('A certificate extension is not a SEQUENCE.');
            }

            $fields = self::children($certificate, $extension['start'], $extension['end']);
            $critical = false;

            if (count($fields) === 3 && $fields[1]['tag'] === self::BOOLEAN) {
                // DER omits a DEFAULT value (X.690, section 11.5), so a written critical flag is TRUE.
                if (! self::boolean($certificate, $fields[1])) {
                    throw self::invalid('A certificate extension writes the default critical flag FALSE.');
                }

                $critical = true;
                $fields = [$fields[0], $fields[2]];
            }

            if (count($fields) !== 2 || $fields[0]['tag'] !== self::OBJECT_IDENTIFIER || $fields[1]['tag'] !== self::OCTET_STRING) {
                throw self::invalid('A certificate extension does not have an OID, an optional critical flag, and a value.');
            }

            $oid = self::content($certificate, $fields[0]);

            // The prefix keeps every key a string; PHP would turn an OID such as "123" into an integer key.
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
        } elseif ($year < 2050) {
            // RFC 5280 writes dates through 2049 as UTCTime. This also keeps gmmktime() away from
            // years 0 to 100, which it maps to other centuries.
            throw self::invalid('A GeneralizedTime certificate time is before 2050.');
        }

        if (! checkdate($month, $day, $year) || $hour > 23 || $minute > 59 || $second > 59) {
            throw self::invalid('A certificate time is not a valid date and time.');
        }

        $timestamp = gmmktime($hour, $minute, $second, $month, $day, $year);

        // Untested: gmmktime() fails only on platforms without 64-bit time, which composer.json refuses.
        return $timestamp !== false ? $timestamp : throw self::invalid('A certificate time is out of range.');
    }

    /**
     * The named curve of an id-ecPublicKey SubjectPublicKeyInfo, as OID content bytes, or null.
     *
     * @param  Element  $element
     */
    private static function curve(string $data, array $element): ?string
    {
        $parts = self::children($data, $element['start'], $element['end']);

        if (count($parts) !== 2 || $parts[0]['tag'] !== self::SEQUENCE || $parts[1]['tag'] !== self::BIT_STRING) {
            throw self::invalid('A certificate public key is not an algorithm and a BIT STRING.');
        }

        $algorithm = self::children($data, $parts[0]['start'], $parts[0]['end']);

        if (count($algorithm) !== 2 || $algorithm[0]['tag'] !== self::OBJECT_IDENTIFIER || $algorithm[1]['tag'] !== self::OBJECT_IDENTIFIER
            || self::content($data, $algorithm[0]) !== self::EC_PUBLIC_KEY) {
            return null;
        }

        return self::content($data, $algorithm[1]);
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
