<?php

declare(strict_types=1);

namespace AppAttest\Internal;

use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;

/**
 * @internal Authenticator data (WebAuthn, section 6.1) as App Attest writes it.
 *
 * Layout: RP ID hash (32 bytes), flags (1), counter (4, big-endian). An
 * attestation adds the AAGUID (16), the credential ID length (2), the
 * credential ID, and the COSE public key. Both may end with a CBOR map of
 * extensions. Apple writes the extensions without setting the ED flag, so the
 * parser reads them whenever bytes remain.
 */
final readonly class AuthenticatorData
{
    private const string CATEGORY = 'apple_validation_category_01';

    private const string BUNDLE_VERSION = 'apple_bundle_version_01';

    private function __construct(
        public string $rpIdHash,
        public int $counter,
        public string $aaguid,
        public string $credentialId,
        public ?int $validationCategory,
        public ?string $bundleVersion,
    ) {}

    /** Parses the authenticator data of an attestation. */
    public static function attestation(string $data): self
    {
        $offset = 37;
        self::need($data, $offset, 18);
        $aaguid = substr($data, $offset, 16);
        $length = self::uint16(substr($data, $offset + 16, 2));
        $offset += 18;
        self::need($data, $offset, $length);
        $credentialId = substr($data, $offset, $length);
        $offset += $length;
        [$key, $offset] = Cbor::decodePrefix($data, $offset);

        if (! is_array($key) || array_is_list($key)) {
            throw self::malformed('The credential public key is not a CBOR map.');
        }

        return self::create($data, $offset, $aaguid, $credentialId);
    }

    /** Parses the authenticator data of an assertion. */
    public static function assertion(string $data): self
    {
        return self::create($data, 37, '', '');
    }

    private static function create(string $data, int $offset, string $aaguid, string $credentialId): self
    {
        if (strlen($data) < 37) {
            throw self::malformed('The authenticator data is shorter than 37 bytes.');
        }

        $category = null;
        $version = null;

        if ($offset < strlen($data)) {
            $extensions = Cbor::decode(substr($data, $offset));

            if (! is_array($extensions) || ($extensions !== [] && array_is_list($extensions))) {
                throw self::malformed('The authenticator data extensions are not a CBOR map.');
            }

            $category = self::category($extensions[self::CATEGORY] ?? null);
            $version = $extensions[self::BUNDLE_VERSION] ?? null;

            if ($version !== null && ! is_string($version)) {
                throw self::malformed('The bundle version extension is not a text string.');
            }
        }

        return new self(
            substr($data, 0, 32),
            self::uint32(substr($data, 33, 4)),
            $aaguid,
            $credentialId,
            $category,
            $version,
        );
    }

    /** Apple writes the category as a 4-byte little-endian byte string; an unsigned integer is also accepted. */
    private static function category(mixed $value): ?int
    {
        if ($value === null) {
            return null;
        }

        if ($value instanceof ByteString && strlen($value->value) === 4) {
            return self::uint32(strrev($value->value));
        }

        if (is_int($value) && $value >= 0 && $value <= 0xFFFFFFFF) {
            return $value;
        }

        throw self::malformed('The validation category extension is not a 32-bit unsigned integer.');
    }

    private static function need(string $data, int $offset, int $length): void
    {
        if (strlen($data) - $offset < $length) {
            throw self::malformed('The authenticator data is truncated.');
        }
    }

    /** Reads 2 big-endian bytes. */
    private static function uint16(string $bytes): int
    {
        return (ord($bytes[0]) << 8) | ord($bytes[1]);
    }

    /** Reads 4 big-endian bytes. */
    private static function uint32(string $bytes): int
    {
        return (ord($bytes[0]) << 24) | (ord($bytes[1]) << 16) | (ord($bytes[2]) << 8) | ord($bytes[3]);
    }

    private static function malformed(string $message): VerificationException
    {
        return VerificationException::because(Failure::MalformedInput, $message);
    }
}
