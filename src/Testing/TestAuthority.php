<?php

declare(strict_types=1);

namespace AppAttest\Testing;

use AppAttest\AppId;
use AppAttest\Environment;
use AppAttest\ValidationCategory;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use RuntimeException;

/**
 * A test certificate authority shaped like Apple's App Attest CA: a P-384 root
 * and intermediate that issue P-256 credential certificates with the nonce
 * extension. Pass rootPem() to the Verifier as trustAnchor in your tests.
 *
 * For tests only. Never use this class or its root outside a test suite.
 */
final readonly class TestAuthority
{
    private function __construct(
        private string $rootPem,
        private OpenSSLCertificate $intermediate,
        private string $intermediateDer,
        private OpenSSLAsymmetricKey $intermediateKey,
    ) {}

    public static function create(): self
    {
        $rootKey = self::key('secp384r1');
        $root = self::sign(['commonName' => 'Test App Attestation Root CA'], $rootKey, null, $rootKey,
            "basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign", 3650, 'sha384');
        $intermediateKey = self::key('secp384r1');
        $intermediate = self::sign(['commonName' => 'Test App Attestation CA 1'], $intermediateKey, $root, $rootKey,
            "basicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign,cRLSign", 3650, 'sha384');

        return new self(self::pem($root), $intermediate, self::der($intermediate), $intermediateKey);
    }

    /** The PEM root certificate, for the Verifier's trustAnchor argument. */
    public function rootPem(): string
    {
        return $this->rootPem;
    }

    /**
     * A new test device with its own P-256 key.
     *
     * @param  ValidationCategory|null  $category  The apple_validation_category_01 value, or null to omit both extensions.
     */
    public function device(
        AppId $appId,
        Environment $environment = Environment::Production,
        ?ValidationCategory $category = ValidationCategory::TestFlight,
        string $bundleVersion = '1.0',
    ): TestDevice {
        return new TestDevice($this, self::key('prime256v1'), $appId, $environment, $category, $bundleVersion);
    }

    /**
     * @internal Issues a credential certificate for $key with the nonce extension, as DER, followed by the intermediate DER.
     *
     * @return array{string, string}
     */
    public function issue(OpenSSLAsymmetricKey $key, string $keyId, string $nonce): array
    {
        $extension = "\x30\x24\xA1\x22\x04\x20".$nonce;
        $lines = "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\n"
            .'1.2.840.113635.100.8.2 = DER:'.implode(':', str_split(bin2hex($extension), 2));
        $credential = self::sign(['commonName' => bin2hex($keyId)], $key, $this->intermediate, $this->intermediateKey, $lines, 3, 'sha256');

        return [self::der($credential), $this->intermediateDer];
    }

    private static function key(string $curve): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);

        return $key !== false ? $key : throw new RuntimeException('openssl_pkey_new failed.');
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
            $csr = openssl_csr_new($subject + ['organizationName' => 'Test'], $key, $options);
            $certificate = $csr instanceof OpenSSLCertificateSigningRequest
                ? openssl_csr_sign($csr, $issuer, $issuerKey, $days, $options, random_int(1, PHP_INT_MAX))
                : false;

            return $certificate !== false ? $certificate : throw new RuntimeException('Signing a test certificate failed.');
        } finally {
            unlink($config);

            while (openssl_error_string() !== false) {
                // Empty the queue that the CSR calls leave.
            }
        }
    }

    private static function pem(OpenSSLCertificate $certificate): string
    {
        return openssl_x509_export($certificate, $pem) && is_string($pem) ? $pem : throw new RuntimeException('openssl_x509_export failed.');
    }

    private static function der(OpenSSLCertificate $certificate): string
    {
        $der = base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', self::pem($certificate)), true);

        return $der !== false ? $der : throw new RuntimeException('The test certificate is not Base64.');
    }
}
