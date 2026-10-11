<?php

declare(strict_types=1);

namespace AppAttest;

use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;
use AppAttest\Internal\AuthenticatorData;
use AppAttest\Internal\ByteString;
use AppAttest\Internal\Cbor;
use AppAttest\Internal\CertificateChain;
use AppAttest\Internal\Der;
use AppAttest\Internal\OpenSsl;
use DateTimeImmutable;
use DateTimeInterface;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

/**
 * Verifies App Attest attestations and assertions for one App ID and environment,
 * as Apple describes in "Validating apps that connect to your server".
 *
 * Your server still owns: one-time challenges, the client data format, storing
 * each key with its counter (update the counter atomically), refusing a key ID
 * that another account already uses, and the receipt's fraud risk metric.
 */
final readonly class Verifier
{
    /** The largest attestation object accepted, in bytes. Apple's are about 6 KB. */
    public const int MAX_ATTESTATION_BYTES = 32768;

    /** The largest assertion object accepted, in bytes. */
    public const int MAX_ASSERTION_BYTES = 4096;

    /** OID 1.2.840.113635.100.8.2, the App Attest nonce extension, as DER content bytes. */
    private const string NONCE_OID = "\x2A\x86\x48\x86\xF7\x63\x64\x08\x02";

    private OpenSSLCertificate $trustAnchor;

    /** @var list<ValidationCategory>|null */
    private ?array $allowedCategories;

    /**
     * @param  array<mixed>|null  $allowedCategories  A non-empty list of the ValidationCategory values to accept;
     *                                                a list also refuses a missing category. Null accepts every category
     *                                                that ValidationCategory names, and a missing one.
     * @param  string|null  $trustAnchor  A PEM root certificate, for tests only. Null uses the pinned Apple App
     *                                    Attestation Root CA.
     */
    public function __construct(
        private AppId $appId,
        private Environment $environment,
        ?array $allowedCategories = null,
        ?string $trustAnchor = null,
    ) {
        $this->allowedCategories = $allowedCategories === null ? null : self::categoryList($allowedCategories);
        $this->trustAnchor = CertificateChain::anchor($trustAnchor ?? self::appleRoot());
    }

    /**
     * Verifies a key's attestation object.
     *
     * @param  string  $attestation  The attestation object (raw CBOR bytes, not Base64).
     * @param  string  $keyId  The key ID from the app (raw 32 bytes, not Base64).
     * @param  string  $clientDataHash  The exact bytes that the app passed to attestKey() as clientDataHash,
     *                                  normally SHA-256 of your one-time challenge. Compute them on the server.
     * @param  DateTimeInterface|null  $at  The time for the certificate validity checks. Null is now.
     *
     * @throws VerificationException When a check fails.
     */
    public function verifyAttestation(
        string $attestation,
        string $keyId,
        string $clientDataHash,
        ?DateTimeInterface $at = null,
    ): AttestedKey {
        if ($clientDataHash === '') {
            throw new InvalidArgumentException('The client data hash must not be empty.');
        }

        try {
            return $this->attestation($attestation, $keyId, $clientDataHash, $at ?? new DateTimeImmutable);
        } finally {
            OpenSsl::clearErrors();
        }
    }

    /**
     * Verifies an assertion from an attested key.
     *
     * @param  string  $assertion  The assertion object (raw CBOR bytes, not Base64).
     * @param  string  $clientData  The client data that the app hashed with SHA-256 and passed to
     *                              generateAssertion(). Rebuild it on the server from the request.
     * @param  string  $publicKey  The PEM public key from AttestedKey::$publicKey.
     * @param  int  $previousCounter  The stored counter: 0 after attestation, then the last VerifiedAssertion::$counter.
     *
     * @throws VerificationException When a check fails.
     */
    public function verifyAssertion(
        string $assertion,
        string $clientData,
        string $publicKey,
        int $previousCounter,
    ): VerifiedAssertion {
        if ($previousCounter < 0 || $previousCounter > 0xFFFFFFFF) {
            throw new InvalidArgumentException('The previous counter must be a 32-bit unsigned integer.');
        }

        try {
            return $this->assertion($assertion, $clientData, self::publicKey($publicKey), $previousCounter);
        } finally {
            OpenSsl::clearErrors();
        }
    }

    /**
     * @param  array<mixed>  $categories
     * @return list<ValidationCategory>
     */
    private static function categoryList(array $categories): array
    {
        if ($categories === [] || ! array_is_list($categories)) {
            throw new InvalidArgumentException('The allowed categories must be a non-empty list.');
        }

        $list = [];

        foreach ($categories as $category) {
            if (! $category instanceof ValidationCategory) {
                throw new InvalidArgumentException('Each allowed category must be a ValidationCategory.');
            }

            $list[] = $category;
        }

        return $list;
    }

    private static function appleRoot(): string
    {
        $pem = file_get_contents(dirname(__DIR__).'/resources/apple-app-attestation-root-ca.pem');

        if ($pem === false) {
            throw new InvalidArgumentException('The Apple App Attestation Root CA file cannot be read.');
        }

        return $pem;
    }

    private static function publicKey(string $pem): OpenSSLAsymmetricKey
    {
        // The prefix check also stops OpenSSL from reading a "file://" path.
        if (! str_starts_with($pem, '-----BEGIN PUBLIC KEY-----')) {
            throw new InvalidArgumentException('The public key must be a PEM SubjectPublicKeyInfo.');
        }

        $key = OpenSsl::quietly(static fn (): OpenSSLAsymmetricKey|false => openssl_pkey_get_public($pem));
        $details = $key === false ? false : openssl_pkey_get_details($key);

        if ($key === false || ! is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC
            || ! is_array($details['ec'] ?? null) || ($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            throw new InvalidArgumentException('The public key must be an EC P-256 key.');
        }

        return $key;
    }

    /** @return array{string, string} The X9.62 uncompressed point and the PEM public key. */
    private static function credentialKey(OpenSSLCertificate $credential): array
    {
        $key = OpenSsl::quietly(static fn (): OpenSSLAsymmetricKey|false => openssl_pkey_get_public($credential));
        $details = $key === false ? false : openssl_pkey_get_details($key);

        if (! is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC || ! is_string($details['key'] ?? null)
            || ! is_array($details['ec'] ?? null) || ($details['ec']['curve_name'] ?? null) !== 'prime256v1'
            || ! is_string($details['ec']['x'] ?? null) || ! is_string($details['ec']['y'] ?? null)
            || strlen($details['ec']['x']) > 32 || strlen($details['ec']['y']) > 32) {
            throw self::fail(Failure::InvalidCertificate, 'The credential certificate does not have an EC P-256 key.');
        }

        $point = "\x04".str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT).str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);

        return [$point, $details['key']];
    }

    private static function checkSize(string $object, int $limit, string $name): void
    {
        if ($object === '' || strlen($object) > $limit) {
            throw self::fail(Failure::MalformedInput, "The {$name} is empty or larger than {$limit} bytes.");
        }
    }

    /**
     * Returns a map that has exactly the given keys.
     *
     * @param  list<string>  $keys
     * @return array<string, mixed>
     */
    private static function fields(mixed $map, array $keys, string $name): array
    {
        if (! is_array($map) || count($map) !== count($keys)) {
            throw self::fail(Failure::MalformedInput, "The {$name} does not have exactly the keys ".implode(', ', $keys).'.');
        }

        $fields = [];

        foreach ($keys as $key) {
            if (! array_key_exists($key, $map)) {
                throw self::fail(Failure::MalformedInput, "The {$name} has no {$key}.");
            }

            $fields[$key] = $map[$key];
        }

        return $fields;
    }

    private static function bytes(mixed $value, string $name): string
    {
        if (! $value instanceof ByteString) {
            throw self::fail(Failure::MalformedInput, "{$name} is not a byte string.");
        }

        return $value->value;
    }

    private static function fail(Failure $failure, string $message): VerificationException
    {
        return VerificationException::because($failure, $message);
    }

    private function attestation(string $attestation, string $keyId, string $clientDataHash, DateTimeInterface $at): AttestedKey
    {
        self::checkSize($attestation, self::MAX_ATTESTATION_BYTES, 'attestation');

        if (strlen($keyId) !== 32) {
            throw self::fail(Failure::MalformedInput, 'The key ID is not 32 bytes.');
        }

        $object = self::fields(Cbor::decode($attestation), ['fmt', 'attStmt', 'authData'], 'attestation object');

        if ($object['fmt'] !== 'apple-appattest') {
            throw self::fail(Failure::UnsupportedFormat, 'The attestation format is not apple-appattest.');
        }

        $statement = self::fields($object['attStmt'], ['x5c', 'receipt'], 'attestation statement');
        $x5c = $statement['x5c'];

        if (! is_array($x5c) || ! array_is_list($x5c) || count($x5c) !== 2
            || ! $x5c[0] instanceof ByteString || ! $x5c[1] instanceof ByteString) {
            throw self::fail(Failure::MalformedInput, 'x5c is not the credential and intermediate certificates.');
        }

        $receipt = self::bytes($statement['receipt'], 'receipt');
        $authData = self::bytes($object['authData'], 'authData');
        $data = AuthenticatorData::attestation($authData);

        // 1. The certificates lead to the trust anchor.
        $credential = CertificateChain::verify($x5c[0]->value, $x5c[1]->value, $this->trustAnchor, $at);

        // 2–4. The credential certificate's nonce is SHA-256(authData || clientDataHash).
        $nonceExtension = Der::extensions($x5c[0]->value)[self::NONCE_OID]['value']
            ?? throw self::fail(Failure::InvalidCertificate, 'The credential certificate has no App Attest nonce.');

        if (! hash_equals(hash('sha256', $authData.$clientDataHash, true), Der::nonce($nonceExtension))) {
            throw self::fail(Failure::NonceMismatch, 'The nonce does not match the authenticator data and client data hash.');
        }

        // 5. The key ID is SHA-256 of the public key as an X9.62 uncompressed point.
        [$point, $publicKey] = self::credentialKey($credential);

        if (! hash_equals(hash('sha256', $point, true), $keyId)) {
            throw self::fail(Failure::KeyIdMismatch, 'The key ID does not match the credential certificate.');
        }

        // 6. The RP ID hash is SHA-256 of the App ID.
        if (! hash_equals($this->appId->hash(), $data->rpIdHash)) {
            throw self::fail(Failure::AppIdMismatch, 'The RP ID hash does not match the App ID.');
        }

        // 7. A new key has not signed anything.
        if ($data->counter !== 0) {
            throw self::fail(Failure::NonZeroCounter, 'The attestation counter is not 0.');
        }

        // 8. The AAGUID names the expected environment.
        if (! hash_equals($this->environment->aaguid(), $data->aaguid)) {
            throw self::fail(Failure::EnvironmentMismatch, "The key is not from the {$this->environment->value} environment.");
        }

        // 9. The credential ID is the key ID.
        if (! hash_equals($keyId, $data->credentialId)) {
            throw self::fail(Failure::CredentialIdMismatch, 'The credential ID does not match the key ID.');
        }

        return new AttestedKey(
            $keyId,
            $publicKey,
            $receipt,
            $this->environment,
            $this->category($data->validationCategory),
            $data->bundleVersion,
        );
    }

    private function assertion(string $assertion, string $clientData, OpenSSLAsymmetricKey $publicKey, int $previousCounter): VerifiedAssertion
    {
        self::checkSize($assertion, self::MAX_ASSERTION_BYTES, 'assertion');
        $object = self::fields(Cbor::decode($assertion), ['signature', 'authenticatorData'], 'assertion object');
        $signature = self::bytes($object['signature'], 'signature');
        $authenticatorData = self::bytes($object['authenticatorData'], 'authenticatorData');
        $data = AuthenticatorData::assertion($authenticatorData);

        // 1–3. The signature is ECDSA with SHA-256 over nonce = SHA-256(authenticatorData || SHA-256(clientData)).
        $nonce = hash('sha256', $authenticatorData.hash('sha256', $clientData, true), true);
        $valid = OpenSsl::quietly(static fn (): int|false => openssl_verify($nonce, $signature, $publicKey, OPENSSL_ALGO_SHA256));

        if ($valid !== 1) {
            throw self::fail(Failure::InvalidSignature, 'The assertion signature is not valid.');
        }

        // 4. The RP ID hash is SHA-256 of the App ID.
        if (! hash_equals($this->appId->hash(), $data->rpIdHash)) {
            throw self::fail(Failure::AppIdMismatch, 'The RP ID hash does not match the App ID.');
        }

        // 5. The counter increases.
        if ($data->counter <= $previousCounter) {
            throw self::fail(Failure::CounterNotIncreased, 'The assertion counter is not above the stored counter.');
        }

        return new VerifiedAssertion($data->counter, $this->category($data->validationCategory), $data->bundleVersion);
    }

    private function category(?int $value): ?ValidationCategory
    {
        if ($value === null) {
            if ($this->allowedCategories !== null) {
                throw self::fail(Failure::CategoryNotAllowed, 'The authenticator data has no validation category.');
            }

            return null;
        }

        $category = ValidationCategory::tryFrom($value);

        if ($category === null || ($this->allowedCategories !== null && ! in_array($category, $this->allowedCategories, true))) {
            throw self::fail(Failure::CategoryNotAllowed, "The validation category {$value} is not allowed.");
        }

        return $category;
    }
}
