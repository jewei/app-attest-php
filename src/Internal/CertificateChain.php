<?php

declare(strict_types=1);

namespace AppAttest\Internal;

use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;
use DateTimeInterface;
use InvalidArgumentException;
use OpenSSLCertificate;

/**
 * @internal Verifies credential certificate → intermediate → trust anchor.
 *
 * All flags, names, and times come from the certificate DER (Der), not from
 * openssl_x509_parse(), whose text output falls back to raw bytes for values
 * that OpenSSL cannot decode. The checks:
 *
 * - The intermediate is not the trust anchor: not its key, and not self-issued. (ECDSA signatures are
 *   malleable, so a byte comparison could not tell a re-signed copy of the anchor.)
 * - The credential key is EC P-256 and the intermediate key EC P-256 or P-384, checked before OpenSSL
 *   parses any key from the device.
 * - Neither certificate has a critical extension other than basicConstraints and keyUsage.
 * - The intermediate is a CA (basicConstraints cA) with keyCertSign; the credential certificate is not a CA.
 * - Each issuer name equals the next certificate's subject name, byte for byte.
 * - All three certificates are valid at the check time.
 * - The anchor's key signed the intermediate, then the intermediate's key signed
 *   the credential certificate. No untrusted key is used before it is authenticated.
 *
 * @phpstan-import-type Extension from Der
 */
final class CertificateChain
{
    /**
     * @return array{certificate: OpenSSLCertificate, extensions: list<Extension>} The credential certificate.
     */
    public static function verify(string $credentialDer, string $intermediateDer, TrustAnchor $anchor, DateTimeInterface $at): array
    {
        $credential = Der::certificate($credentialDer);
        $intermediate = Der::certificate($intermediateDer);

        if ($intermediate['publicKey'] === $anchor->fields['publicKey'] || $intermediate['issuer'] === $intermediate['subject']) {
            throw self::invalid('The intermediate certificate is the trust anchor or self-issued.');
        }

        if ($credential['curve'] !== Der::P256 || ! in_array($intermediate['curve'], [Der::P256, Der::P384], true)) {
            throw self::invalid('A certificate key is not EC P-256 (credential) or EC P-256 or P-384 (intermediate).');
        }

        foreach (['credential' => $credential, 'intermediate' => $intermediate] as $name => $fields) {
            foreach ($fields['extensions'] as $extension) {
                if ($extension['critical'] && $extension['oid'] !== Der::BASIC_CONSTRAINTS && $extension['oid'] !== Der::KEY_USAGE) {
                    throw self::invalid("The {$name} certificate has a critical extension that the verifier does not check.");
                }
            }
        }

        if (! self::isCa($intermediate['extensions']) || ! self::allowsCertificateSigning($intermediate['extensions'])) {
            throw self::invalid('The intermediate certificate is not a CA that may sign certificates.');
        }

        if (self::isCa($credential['extensions'])) {
            throw self::invalid('The credential certificate is a CA certificate.');
        }

        if ($intermediate['issuer'] !== $anchor->fields['subject'] || $credential['issuer'] !== $intermediate['subject']) {
            throw self::invalid('An issuer name is not the next certificate\'s subject name.');
        }

        foreach (['credential' => $credential, 'intermediate' => $intermediate, 'trust anchor' => $anchor->fields] as $name => $fields) {
            if ($at->getTimestamp() < $fields['notBefore'] || $at->getTimestamp() > $fields['notAfter']) {
                throw self::invalid("The {$name} certificate is not valid at the check time.");
            }
        }

        $intermediateCertificate = self::read($intermediateDer);
        self::checkSignature($intermediateCertificate, $anchor->certificate, 'intermediate');
        $credentialCertificate = self::read($credentialDer);
        self::checkSignature($credentialCertificate, $intermediateCertificate, 'credential');

        return ['certificate' => $credentialCertificate, 'extensions' => $credential['extensions']];
    }

    /** Reads and checks a trust anchor PEM. Throws InvalidArgumentException: the anchor is server configuration. */
    public static function anchor(string $pem): TrustAnchor
    {
        if (! str_starts_with($pem, '-----BEGIN CERTIFICATE-----')) {
            throw new InvalidArgumentException('The trust anchor must be a PEM certificate.');
        }

        $certificate = OpenSsl::quietly(static fn (): OpenSSLCertificate|false => openssl_x509_read($pem));
        $exported = $certificate === false ? false : OpenSsl::quietly(static fn (): string|false => openssl_x509_export($certificate, $out) && is_string($out) ? $out : false);
        $der = $exported === false ? false : base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', $exported), true);

        // The export and Base64 parts are untested: OpenSSL exports any certificate that it read.
        if ($certificate === false || $der === false) {
            throw new InvalidArgumentException('The trust anchor cannot be read.');
        }

        try {
            $fields = Der::certificate($der);
            $constraints = self::constraints($fields['extensions']);
            $signs = self::allowsCertificateSigning($fields['extensions']);
        } catch (VerificationException) {
            throw new InvalidArgumentException('The trust anchor is not a well-formed version 3 DER certificate.');
        }

        if (! $constraints['ca'] || ($constraints['pathLength'] ?? 1) < 1 || ! $signs) {
            throw new InvalidArgumentException('The trust anchor is not a CA that may sign a CA certificate.');
        }

        return new TrustAnchor($certificate, $fields);
    }

    /** @param list<Extension> $extensions */
    private static function isCa(array $extensions): bool
    {
        return self::constraints($extensions)['ca'];
    }

    /**
     * basicConstraints, or "not a CA" when the extension is absent (RFC 5280, section 4.2.1.9).
     *
     * @param  list<Extension>  $extensions
     * @return array{ca: bool, pathLength: ?int}
     */
    private static function constraints(array $extensions): array
    {
        $value = Der::extensionValue($extensions, Der::BASIC_CONSTRAINTS);

        return $value === null ? ['ca' => false, 'pathLength' => null] : Der::basicConstraints($value);
    }

    /**
     * keyCertSign is required. Apple's CA certificates have keyUsage, so its absence is refused.
     *
     * @param  list<Extension>  $extensions
     */
    private static function allowsCertificateSigning(array $extensions): bool
    {
        $value = Der::extensionValue($extensions, Der::KEY_USAGE);

        return $value !== null && Der::allowsCertificateSigning($value);
    }

    private static function read(string $der): OpenSSLCertificate
    {
        $pem = "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END CERTIFICATE-----\n";
        $certificate = OpenSsl::quietly(static fn (): OpenSSLCertificate|false => openssl_x509_read($pem));

        if ($certificate === false) {
            throw self::invalid('A certificate cannot be read.');
        }

        return $certificate;
    }

    private static function checkSignature(OpenSSLCertificate $certificate, OpenSSLCertificate $issuer, string $name): void
    {
        if (OpenSsl::quietly(static fn (): int => openssl_x509_verify($certificate, $issuer)) !== 1) {
            throw self::invalid("The {$name} certificate's signature is not valid.");
        }
    }

    private static function invalid(string $message): VerificationException
    {
        return VerificationException::because(Failure::InvalidCertificate, $message);
    }
}
