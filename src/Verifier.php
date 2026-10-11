<?php

declare(strict_types=1);

namespace AppAttest;

use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;
use AppAttest\Internal\AuthenticatorData;
use AppAttest\Internal\ByteString;
use AppAttest\Internal\Cbor;
use AppAttest\Internal\CborMap;
use AppAttest\Internal\CertificateChain;
use AppAttest\Internal\Der;
use AppAttest\Internal\OpenSsl;
use AppAttest\Internal\TrustAnchor;
use DateTimeImmutable;
use DateTimeInterface;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use RuntimeException;

/**
 * Verifies App Attest attestations and assertions for one App ID and environment,
 * as Apple describes in "Validating apps that connect to your server".
 *
 * Your server still owns: one-time challenges, the client data format, storing
 * each key with its environment and counter (update the counter atomically),
 * refusing a key ID that another account already uses, checking the bundle
 * version if you need a minimum, and the receipt's fraud risk metric.
 */
final readonly class Verifier
{
    /** The largest attestation object accepted, in bytes. Apple's are about 6 KB. */
    public const int MAX_ATTESTATION_BYTES = 32768;

    /** The largest assertion object accepted, in bytes. */
    public const int MAX_ASSERTION_BYTES = 4096;

    /** OID 1.2.840.113635.100.8.2, the App Attest nonce extension, as DER content bytes. */
    private const string NONCE_OID = "\x2A\x86\x48\x86\xF7\x63\x64\x08\x02";

    /** OID 1.2.840.113635.100.8.7, the App Attest extension that names the platform, as DER content bytes. */
    private const string PLATFORM_OID = "\x2A\x86\x48\x86\xF7\x63\x64\x08\x07";

    /** The platform name that iPhone and iPad keys carry. */
    private const string IOS_PLATFORM = 'iphoneos';

    /** OID 1.2.840.113635.100.8.6, the key's access-control (aclBlob) extension, as DER content bytes. */
    private const string ACL_OID = "\x2A\x86\x48\x86\xF7\x63\x64\x08\x06";

    /** The aclBlob that Apple documents for macOS keys (Base64): every App Attest key on macOS 27 has this policy. */
    private const string MACOS_ACL = 'MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB';

    private TrustAnchor $trustAnchor;

    /**
     * @param  CategoryPolicy  $categories  Which validation categories to accept, for example
     *                                      CategoryPolicy::onlyOrMissing(ValidationCategory::AppStore, ValidationCategory::TestFlight)
     *                                      (devices on iOS 26 and earlier write no category).
     * @param  string|null  $trustAnchor  A PEM root certificate, for tests with your own test CA. Null uses the
     *                                    pinned Apple App Attestation Root CA. Never set it in production.
     *
     * @throws InvalidArgumentException When an argument is not valid.
     * @throws RuntimeException On a 32-bit PHP build, or when the package's root certificate file is missing.
     */
    public function __construct(
        private AppId $appId,
        private Environment $environment,
        private CategoryPolicy $categories,
        ?string $trustAnchor = null,
    ) {
        // Untested: Composer's php-64bit requirement already refuses 32-bit builds.
        if (PHP_INT_SIZE < 8) {
            throw new RuntimeException('App Attest verification needs a 64-bit PHP build.');
        }

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
     * @throws InvalidArgumentException When $clientDataHash is empty.
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

        self::checkSize($attestation, self::MAX_ATTESTATION_BYTES, 'attestation');

        if (strlen($keyId) !== 32) {
            throw self::fail(Failure::MalformedInput, 'The key ID is not 32 bytes.');
        }

        // 1. The object has Apple's structure.
        $object = self::fields(Cbor::decode($attestation), ['fmt', 'attStmt', 'authData'], 'attestation object');

        if ($object['fmt'] !== 'apple-appattest') {
            throw self::fail(Failure::UnsupportedFormat, 'The attestation format is not apple-appattest.');
        }

        $statement = self::fields($object['attStmt'], ['x5c', 'receipt'], 'attestation statement');
        $x5c = $statement['x5c'];

        if (! is_array($x5c) || count($x5c) !== 2 || ! ($x5c[0] ?? null) instanceof ByteString || ! ($x5c[1] ?? null) instanceof ByteString) {
            throw self::fail(Failure::MalformedInput, 'x5c is not an array of the credential and intermediate certificates.');
        }

        $receipt = self::bytes($statement['receipt'], 'receipt');
        $authData = self::bytes($object['authData'], 'authData');
        $data = AuthenticatorData::attestation($authData);

        // 2. The certificates lead to the trust anchor.
        $credential = CertificateChain::verify($x5c[0]->value, $x5c[1]->value, $this->trustAnchor, $at ?? new DateTimeImmutable);

        // 3. The credential certificate's nonce is SHA-256(authData || clientDataHash).
        $nonceExtension = Der::extensionValue($credential['extensions'], self::NONCE_OID)
            ?? throw self::fail(Failure::InvalidCertificate, 'The credential certificate has no App Attest nonce.');

        if (! hash_equals(hash('sha256', $authData.$clientDataHash, true), Der::nonce($nonceExtension))) {
            throw self::fail(Failure::NonceMismatch, 'The nonce does not match the authenticator data and client data hash.');
        }

        // A key whose certificate names another platform, such as macOS, needs checks that this package does
        // not make (the aclBlob extension), so it is refused. Certificates without the field are accepted.
        $platformExtension = Der::extensionValue($credential['extensions'], self::PLATFORM_OID);
        $platform = $platformExtension === null ? null : Der::platform($platformExtension);

        $acl = Der::extensionValue($credential['extensions'], self::ACL_OID);
        $macAcl = (string) base64_decode(self::MACOS_ACL, true);

        if (($platform !== null && $platform !== self::IOS_PLATFORM) || ($acl !== null && str_contains($acl, $macAcl))) {
            throw self::fail(Failure::UnsupportedPlatform, 'The key is from a platform other than iPhone and iPad.');
        }

        // 4. The key ID is SHA-256 of the public key as an X9.62 uncompressed point.
        [$point, $publicKey] = self::credentialKey($credential['certificate']);

        if (! hash_equals(hash('sha256', $point, true), $keyId)) {
            throw self::fail(Failure::KeyIdMismatch, 'The key ID does not match the credential certificate.');
        }

        // 5. The RP ID hash is SHA-256 of the App ID.
        if (! hash_equals($this->appId->hash(), $data->rpIdHash)) {
            throw self::fail(Failure::AppIdMismatch, 'The RP ID hash does not match the App ID.');
        }

        // 6. A new key has not signed anything.
        if ($data->counter !== 0) {
            throw self::fail(Failure::NonZeroCounter, 'The attestation counter is not 0.');
        }

        // 7. The AAGUID names the expected environment.
        if (! hash_equals($this->environment->aaguid(), $data->aaguid)) {
            throw self::fail(Failure::EnvironmentMismatch, "The key is not from the {$this->environment->value} environment.");
        }

        // 8. The credential ID is the key ID.
        if (! hash_equals($keyId, $data->credentialId)) {
            throw self::fail(Failure::CredentialIdMismatch, 'The credential ID does not match the key ID.');
        }

        // 9. The validation category passes the policy.
        return new AttestedKey(
            $keyId,
            $publicKey,
            $receipt,
            $this->environment,
            $this->category($data->validationCategory),
            $data->bundleVersion,
        );
    }

    /**
     * Verifies an assertion from an attested key.
     *
     * @param  string  $assertion  The assertion object (raw CBOR bytes, not Base64).
     * @param  string  $clientData  The client data that the app hashed with SHA-256 and passed to
     *                              generateAssertion(). Rebuild it on the server from the request.
     * @param  string  $publicKey  The stored AttestedKey::$publicKey (PEM).
     * @param  int  $previousCounter  The stored counter: 0 after attestation, then the last VerifiedAssertion::$counter.
     * @param  Environment  $keyEnvironment  The stored AttestedKey::$environment. An assertion does not name its
     *                                       environment, so a key from another environment is refused here.
     *
     * @throws VerificationException When a check fails.
     * @throws InvalidArgumentException When $publicKey is not an EC P-256 PEM or $previousCounter is out of range.
     */
    public function verifyAssertion(
        string $assertion,
        string $clientData,
        string $publicKey,
        int $previousCounter,
        Environment $keyEnvironment,
    ): VerifiedAssertion {
        if ($previousCounter < 0 || $previousCounter > 0xFFFFFFFF) {
            throw new InvalidArgumentException('The previous counter must be a 32-bit unsigned integer.');
        }

        $key = self::publicKey($publicKey);

        if ($keyEnvironment !== $this->environment) {
            throw self::fail(Failure::EnvironmentMismatch, "The key is not from the {$this->environment->value} environment.");
        }

        // 1. The object has Apple's structure.
        self::checkSize($assertion, self::MAX_ASSERTION_BYTES, 'assertion');
        $object = self::fields(Cbor::decode($assertion), ['signature', 'authenticatorData'], 'assertion object');
        $signature = self::bytes($object['signature'], 'signature');
        $authenticatorData = self::bytes($object['authenticatorData'], 'authenticatorData');
        $data = AuthenticatorData::assertion($authenticatorData);

        // 2. The signature is ECDSA with SHA-256 over nonce = SHA-256(authenticatorData || SHA-256(clientData)).
        $nonce = hash('sha256', $authenticatorData.hash('sha256', $clientData, true), true);
        $valid = OpenSsl::quietly(static fn (): int|false => openssl_verify($nonce, $signature, $key, OPENSSL_ALGO_SHA256));

        if ($valid !== 1) {
            throw self::fail(Failure::InvalidSignature, 'The assertion signature is not valid.');
        }

        // 3. The RP ID hash is SHA-256 of the App ID.
        if (! hash_equals($this->appId->hash(), $data->rpIdHash)) {
            throw self::fail(Failure::AppIdMismatch, 'The RP ID hash does not match the App ID.');
        }

        // 4. The counter increases.
        if ($data->counter <= $previousCounter) {
            throw self::fail(Failure::CounterNotIncreased, 'The assertion counter is not above the stored counter.');
        }

        // 5. The validation category passes the policy.
        return new VerifiedAssertion($data->counter, $this->category($data->validationCategory), $data->bundleVersion);
    }

    private static function appleRoot(): string
    {
        $path = dirname(__DIR__).'/resources/apple-app-attestation-root-ca.pem';
        $pem = is_file($path) && is_readable($path) ? file_get_contents($path) : false;

        // Untested: only an incomplete install reaches this.
        if ($pem === false) {
            throw new RuntimeException('The package is incomplete: the Apple App Attestation Root CA file cannot be read.');
        }

        return $pem;
    }

    private static function publicKey(string $pem): OpenSSLAsymmetricKey
    {
        // Exactly one PUBLIC KEY block of a sane size: OpenSSL would read a "file://" path, and it reads a
        // certificate in the same string before the key. An EC P-256 PEM has about 180 bytes.
        if (strlen($pem) > 1024 || preg_match('~\A-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?\z~', $pem) !== 1) {
            throw new InvalidArgumentException('The public key must be one PEM SubjectPublicKeyInfo block.');
        }

        $key = OpenSsl::quietly(static fn (): OpenSSLAsymmetricKey|false => openssl_pkey_get_public($pem));

        if ($key === false || self::curve($key) !== 'prime256v1') {
            throw new InvalidArgumentException('The public key must be an EC P-256 key.');
        }

        return $key;
    }

    /** @return array{string, string} The X9.62 uncompressed point and the PEM public key. */
    private static function credentialKey(OpenSSLCertificate $credential): array
    {
        $key = OpenSsl::quietly(static fn (): OpenSSLAsymmetricKey|false => openssl_pkey_get_public($credential));
        $details = $key === false ? false : OpenSsl::quietly(static fn (): array|false => openssl_pkey_get_details($key));

        if ($key === false || self::curve($key) !== 'prime256v1' || ! is_array($details) || ! is_string($details['key'] ?? null)
            || ! is_array($details['ec'] ?? null) || ! is_string($details['ec']['x'] ?? null) || ! is_string($details['ec']['y'] ?? null)) {
            throw self::fail(Failure::InvalidCertificate, 'The credential certificate does not have an EC P-256 key.');
        }

        // CertificateChain already refused a key that is not EC P-256 (from the DER), so these checks repeat it
        // for an OpenSSL build that reads the key differently. OpenSSL returns the coordinates without leading
        // zero bytes.
        $point = "\x04".str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT).str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);

        return [$point, $details['key']];
    }

    /** The curve name of an EC key, or null for another key type. */
    private static function curve(OpenSSLAsymmetricKey $key): ?string
    {
        $details = OpenSsl::quietly(static fn (): array|false => openssl_pkey_get_details($key));

        // Defensive shape checks: the DER check already proved an EC key on a named curve.
        if (! is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC || ! is_array($details['ec'] ?? null)) {
            return null;
        }

        return is_string($details['ec']['curve_name'] ?? null) ? $details['ec']['curve_name'] : null;
    }

    private static function checkSize(string $object, int $limit, string $name): void
    {
        // Empty input would also fail to decode; the check names the problem directly.
        if ($object === '' || strlen($object) > $limit) {
            throw self::fail(Failure::MalformedInput, "The {$name} is empty or larger than {$limit} bytes.");
        }
    }

    /**
     * Returns the entries of a map that has exactly the given keys.
     *
     * @param  list<string>  $keys
     * @return array<string, mixed>
     */
    private static function fields(mixed $map, array $keys, string $name): array
    {
        if (! $map instanceof CborMap || ! $map->hasExactly($keys)) {
            throw self::fail(Failure::MalformedInput, "The {$name} is not a map with exactly the keys ".implode(', ', $keys).'.');
        }

        $fields = [];

        foreach ($keys as $key) {
            $fields[$key] = $map->get($key);
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

    private function category(?int $value): ?ValidationCategory
    {
        $category = $value === null ? null : ValidationCategory::tryFrom($value);

        // A value that ValidationCategory does not name is refused by every policy.
        if (($value !== null && $category === null) || ! $this->categories->allows($category)) {
            throw self::fail(Failure::CategoryNotAllowed, $value === null
                ? 'The authenticator data has no validation category.'
                : "The validation category {$value} is not allowed.");
        }

        return $category;
    }
}
