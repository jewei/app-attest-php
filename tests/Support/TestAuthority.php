<?php

declare(strict_types=1);

namespace AppAttest\Tests\Support;

use AppAttest\AppId;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use RuntimeException;

/**
 * A certificate authority shaped like Apple's: a P-384 root, a P-384 intermediate,
 * and P-256 credential certificates with the App Attest nonce extension.
 * It builds attestations and assertions that tests can break one check at a time.
 */
final class TestAuthority
{
    public const string CA_EXTENSIONS = "basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign";
    private static ?self $shared = null;

    private function __construct(
        public readonly string $rootPem,
        public readonly string $rootDer,
        private readonly OpenSSLAsymmetricKey $rootKey,
        private readonly OpenSSLCertificate $root,
        public readonly string $intermediateDer,
        private readonly OpenSSLCertificate $intermediate,
        private readonly OpenSSLAsymmetricKey $intermediateKey,
    ) {}

    public static function shared(): self
    {
        return self::$shared ??= self::create();
    }

    /**
     * @param  string  $intermediateExtensions  OpenSSL extension lines for the intermediate.
     * @param  string  $rootExtensions  OpenSSL extension lines for the root.
     */
    public static function create(
        string $intermediateExtensions = "basicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign,cRLSign",
        int $rootDays = 3650,
        int $intermediateDays = 3650,
        string $rootExtensions = self::CA_EXTENSIONS,
        string $intermediateCurve = 'secp384r1',
    ): self {
        $rootKey = self::key('secp384r1');
        $root = self::sign(['commonName' => 'Test App Attestation Root CA', 'organizationName' => 'Test'], $rootKey, null, $rootKey,
            $rootExtensions, $rootDays, 'sha384');

        $intermediateKey = self::key($intermediateCurve);
        $intermediate = self::sign(['commonName' => 'Test App Attestation CA 1', 'organizationName' => 'Test'], $intermediateKey, $root, $rootKey,
            $intermediateExtensions, $intermediateDays, 'sha384');

        return new self(self::pem($root), self::der($root), $rootKey, $root, self::der($intermediate), $intermediate, $intermediateKey);
    }

    /** OpenSSL extension lines for the App Attest platform field ([1026]) with $platform. */
    public static function platformExtension(string $platform, string $extraFields = ''): string
    {
        $field = "\xBF\x88\x02".self::length(strlen($platform) + 2)."\x04".self::length(strlen($platform)).$platform;
        $fields = $extraFields.$field;

        return '1.2.840.113635.100.8.7 = DER:'.self::hexColons("\x30".self::length(strlen($fields)).$fields);
    }

    /** OpenSSL extension lines for the access-control (aclBlob) extension 1.2.840.113635.100.8.6 with $blob. */
    public static function aclExtension(string $blob): string
    {
        $octets = "\x04".self::length(strlen($blob)).$blob;
        $tagged = "\xA3".self::length(strlen($octets)).$octets;

        return '1.2.840.113635.100.8.6 = DER:'.self::hexColons("\x30".self::length(strlen($tagged)).$tagged);
    }

    /** A P-256 key from tests/Fixtures. */
    public static function fixtureKey(string $name): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_private((string) file_get_contents(__DIR__.'/../Fixtures/'.$name.'.pem'));

        if ($key === false) {
            throw new RuntimeException("The fixture key {$name} cannot be read.");
        }

        return $key;
    }

    /**
     * Builds an assertion object. Options: rpIdHash, flags (one byte) (strings), extensions (map, raw string, or null for none),
     * signWith (OpenSSLAsymmetricKey), signature (string), mutate (Closure(AssertionObject): void).
     *
     * @param  array<mixed>  $options
     */
    public static function assertion(OpenSSLAsymmetricKey $key, AppId $appId, string $clientData, int $counter, array $options = []): string
    {
        $extensions = self::extensions($options);
        // Real assertions with extensions set AT and ED (0xC0). The flags option tests other values.
        $flags = Options::string($options, 'flags', $extensions === '' ? "\x40" : "\xC0");
        $authenticatorData = Options::string($options, 'rpIdHash', $appId->hash()).$flags.pack('N', $counter).$extensions;
        $nonce = hash('sha256', $authenticatorData.hash('sha256', $clientData, true), true);

        if (! openssl_sign($nonce, $signature, Options::key($options, 'signWith') ?? $key, OPENSSL_ALGO_SHA256) || ! is_string($signature)) {
            throw new RuntimeException('openssl_sign failed.');
        }

        $object = new AssertionObject(new Bytes(Options::string($options, 'signature', $signature)), new Bytes($authenticatorData));
        Options::closure($options, 'mutate')?->__invoke($object);

        return $object->encode();
    }

    public static function key(string $curve = 'prime256v1'): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);

        if ($key === false) {
            throw new RuntimeException('openssl_pkey_new failed.');
        }

        return $key;
    }

    public static function publicPem(OpenSSLAsymmetricKey $key): string
    {
        $details = openssl_pkey_get_details($key);

        if (! is_array($details) || ! is_string($details['key'] ?? null)) {
            throw new RuntimeException('openssl_pkey_get_details failed.');
        }

        return $details['key'];
    }

    /** A copy of the root: the same key and name under a new serial number, so its DER differs (DER). */
    public function rootCopy(): string
    {
        return self::der(self::sign(['commonName' => 'Test App Attestation Root CA', 'organizationName' => 'Test'], $this->rootKey, null, $this->rootKey,
            self::CA_EXTENSIONS, 3650, 'sha384'));
    }

    /**
     * An intermediate that the root's key signed under another issuer name (DER), so that only the name
     * check can refuse it.
     */
    public function intermediateIssuedUnder(string $issuerCommonName): string
    {
        $otherRoot = self::sign(['commonName' => $issuerCommonName, 'organizationName' => 'Test'], $this->rootKey, null, $this->rootKey,
            self::CA_EXTENSIONS, 3650, 'sha384');

        return self::der(self::sign(['commonName' => 'Test App Attestation CA 1', 'organizationName' => 'Test'], $this->intermediateKey, $otherRoot, $this->rootKey,
            "basicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign,cRLSign", 3650, 'sha384'));
    }

    /** Another intermediate certificate for the same key, with another subject name (DER). */
    public function intermediateWithSubject(string $commonName): string
    {
        return self::der(self::sign(['commonName' => $commonName, 'organizationName' => 'Test'], $this->intermediateKey, $this->root, $this->rootKey,
            "basicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign,cRLSign", 3650, 'sha384'));
    }

    /**
     * Builds an attestation object. Options: key (OpenSSLAsymmetricKey), counter (int), aaguid, credentialId,
     * rpIdHash, coseKey (raw CBOR), receipt (strings), extensions (map, raw string, or null for none), nonce
     * (string, or null for no extension), nonceExtension (raw DER), credentialExtensions (OpenSSL lines),
     * credentialDays (int), curve (string), issuer ('intermediate' or 'root'), mutate (Closure(AttestationObject): void).
     *
     * @param  array<mixed>  $options
     * @return array{attestation: string, keyId: string, key: OpenSSLAsymmetricKey, publicKey: string, credential: string}
     */
    public function attest(AppId $appId, string $clientDataHash, array $options = []): array
    {
        $key = Options::key($options, 'key') ?? self::key(Options::string($options, 'curve', 'prime256v1'));
        $point = self::point($key);
        $keyId = hash('sha256', $point, true);
        $credentialId = Options::string($options, 'credentialId', $keyId);

        $authData = Options::string($options, 'rpIdHash', $appId->hash())
            ."\x40".pack('N', Options::int($options, 'counter', 0))
            .Options::string($options, 'aaguid', "appattest\0\0\0\0\0\0\0")
            .pack('n', strlen($credentialId)).$credentialId
            .Options::string($options, 'coseKey', CborEncoder::encode([1 => 2, 3 => -7, -1 => 1, -2 => new Bytes(substr($point, 1, 32)), -3 => new Bytes(substr($point, 33, 32))]))
            .self::extensions($options);

        $nonce = Options::nullableString($options, 'nonce', hash('sha256', $authData.$clientDataHash, true));
        $lines = Options::string($options, 'credentialExtensions', "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature");
        $nonceExtension = Options::nullableString($options, 'nonceExtension', null);

        if ($nonceExtension !== null) {
            $lines .= "\n1.2.840.113635.100.8.2 = DER:".self::hexColons($nonceExtension);
        } elseif ($nonce !== null) {
            $octets = "\x04".chr(strlen($nonce)).$nonce;
            $tagged = "\xA1".chr(strlen($octets)).$octets;
            $lines .= "\n1.2.840.113635.100.8.2 = DER:".self::hexColons("\x30".chr(strlen($tagged)).$tagged);
        }

        [$issuer, $issuerKey] = Options::string($options, 'issuer', 'intermediate') === 'root'
            ? [$this->root, $this->rootKey]
            : [$this->intermediate, $this->intermediateKey];
        $credential = self::der(self::sign(['commonName' => bin2hex($keyId)], $key, $issuer, $issuerKey, $lines, Options::int($options, 'credentialDays', 3), 'sha256'));

        $object = new AttestationObject('apple-appattest', [new Bytes($credential), new Bytes($this->intermediateDer)], new Bytes(Options::string($options, 'receipt', 'test receipt')), new Bytes($authData));
        Options::closure($options, 'mutate')?->__invoke($object);

        return [
            'attestation' => $object->encode(),
            'keyId' => $keyId,
            'key' => $key,
            'publicKey' => self::publicPem($key),
            'credential' => $credential,
        ];
    }

    /** A DER length. */
    private static function length(int $length): string
    {
        return match (true) {
            $length < 0x80 => chr($length),
            $length <= 0xFF => "\x81".chr($length),
            default => "\x82".pack('n', $length),
        };
    }

    /** @param array<mixed> $options */
    private static function extensions(array $options): string
    {
        if (! array_key_exists('extensions', $options)) {
            return CborEncoder::encode(['apple_bundle_version_01' => '1.0', 'apple_validation_category_01' => new Bytes("\x02\x00\x00\x00")]);
        }

        $extensions = $options['extensions'];

        return match (true) {
            $extensions === null => '',
            is_string($extensions) => $extensions,
            default => CborEncoder::encode($extensions),
        };
    }

    private static function point(OpenSSLAsymmetricKey $key): string
    {
        $details = openssl_pkey_get_details($key);

        if (! is_array($details) || ! is_array($details['ec'] ?? null)
            || ! is_string($details['ec']['x'] ?? null) || ! is_string($details['ec']['y'] ?? null)) {
            throw new RuntimeException('The key is not an EC key.');
        }

        $size = ($details['ec']['curve_name'] ?? null) === 'secp384r1' ? 48 : 32;

        return "\x04".str_pad($details['ec']['x'], $size, "\0", STR_PAD_LEFT).str_pad($details['ec']['y'], $size, "\0", STR_PAD_LEFT);
    }

    /** @param array<string, string> $subject */
    private static function sign(
        array $subject,
        OpenSSLAsymmetricKey $key,
        ?OpenSSLCertificate $issuer,
        OpenSSLAsymmetricKey $issuerKey,
        string $extensions,
        int $days,
        string $digest,
    ): OpenSSLCertificate {
        $config = tempnam(sys_get_temp_dir(), 'app-attest-test-');

        if ($config === false) {
            throw new RuntimeException('tempnam failed.');
        }

        try {
            file_put_contents($config, "[req]\ndistinguished_name = dn\n[dn]\n[ext]\n{$extensions}\n");
            $options = ['config' => $config, 'x509_extensions' => 'ext', 'digest_alg' => $digest];
            $csr = openssl_csr_new($subject, $key, $options);

            if (! $csr instanceof OpenSSLCertificateSigningRequest) {
                throw new RuntimeException('openssl_csr_new failed: '.openssl_error_string());
            }

            $certificate = openssl_csr_sign($csr, $issuer, $issuerKey, $days, $options, random_int(1, PHP_INT_MAX));

            if ($certificate === false) {
                throw new RuntimeException('openssl_csr_sign failed: '.openssl_error_string());
            }

            return $certificate;
        } finally {
            unlink($config);

            while (openssl_error_string() !== false) {
                // Empty the queue so that tests start clean.
            }
        }
    }

    private static function pem(OpenSSLCertificate $certificate): string
    {
        if (! openssl_x509_export($certificate, $pem) || ! is_string($pem)) {
            throw new RuntimeException('openssl_x509_export failed.');
        }

        return $pem;
    }

    private static function der(OpenSSLCertificate $certificate): string
    {
        $body = preg_replace('/-----[^-]+-----|\s/', '', self::pem($certificate));
        $der = base64_decode((string) $body, true);

        if ($der === false) {
            throw new RuntimeException('The PEM certificate is not Base64.');
        }

        return $der;
    }

    private static function hexColons(string $bytes): string
    {
        return implode(':', str_split(bin2hex($bytes), 2));
    }
}
