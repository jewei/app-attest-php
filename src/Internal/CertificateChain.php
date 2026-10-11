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
 * Checks: each signature with the issuer's key; each issuer name equals the
 * issuer's subject name; all three certificates are valid at the check time;
 * the intermediate is a CA that may sign certificates; the credential
 * certificate is not a CA; neither certificate has a critical extension that
 * this class does not check.
 */
final class CertificateChain
{
    /** Critical extensions that this class checks: basicConstraints and keyUsage. */
    private const array UNDERSTOOD_CRITICAL = ["\x55\x1D\x13", "\x55\x1D\x0F"];

    public static function verify(
        string $credentialDer,
        string $intermediateDer,
        OpenSSLCertificate $anchor,
        DateTimeInterface $at,
    ): OpenSSLCertificate {
        $credential = self::fromDer($credentialDer);
        $intermediate = self::fromDer($intermediateDer);
        self::checkCriticalExtensions($credentialDer);
        self::checkCriticalExtensions($intermediateDer);

        $credentialFields = self::fields($credential);
        $intermediateFields = self::fields($intermediate);
        $anchorFields = self::fields($anchor);

        self::checkIssuedBy($credential, $credentialFields, $intermediate, $intermediateFields, 'credential');
        self::checkIssuedBy($intermediate, $intermediateFields, $anchor, $anchorFields, 'intermediate');

        foreach (['credential' => $credentialFields, 'intermediate' => $intermediateFields, 'trust anchor' => $anchorFields] as $name => $fields) {
            if ($at->getTimestamp() < $fields['validFrom'] || $at->getTimestamp() > $fields['validTo']) {
                throw self::invalid("The {$name} certificate is not valid at the check time.");
            }
        }

        if (self::isCa($credentialFields)) {
            throw self::invalid('The credential certificate is a CA certificate.');
        }

        if (! self::isCa($intermediateFields) || ! self::canSignCertificates($intermediateFields)) {
            throw self::invalid('The intermediate certificate is not a CA that may sign certificates.');
        }

        return $credential;
    }

    /** Reads and checks a trust anchor PEM. Throws InvalidArgumentException: the anchor is server configuration. */
    public static function anchor(string $pem): OpenSSLCertificate
    {
        if (! str_starts_with($pem, '-----BEGIN CERTIFICATE-----')) {
            throw new InvalidArgumentException('The trust anchor must be a PEM certificate.');
        }

        $certificate = OpenSsl::quietly(static fn (): OpenSSLCertificate|false => openssl_x509_read($pem));

        if ($certificate === false) {
            throw new InvalidArgumentException('The trust anchor cannot be read.');
        }

        try {
            $fields = self::fields($certificate);
        } catch (VerificationException) {
            throw new InvalidArgumentException('The trust anchor cannot be read.');
        }

        if (! self::isCa($fields) || ! self::canSignCertificates($fields)) {
            throw new InvalidArgumentException('The trust anchor is not a CA that may sign certificates.');
        }

        return $certificate;
    }

    private static function fromDer(string $der): OpenSSLCertificate
    {
        $outer = Der::element($der, 0, strlen($der));

        if ($outer['tag'] !== Der::SEQUENCE || $outer['end'] !== strlen($der)) {
            throw self::invalid('A certificate is not one DER SEQUENCE.');
        }

        $pem = "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END CERTIFICATE-----\n";
        $certificate = OpenSsl::quietly(static fn (): OpenSSLCertificate|false => openssl_x509_read($pem));

        if ($certificate === false) {
            throw self::invalid('A certificate cannot be read.');
        }

        return $certificate;
    }

    private static function checkCriticalExtensions(string $der): void
    {
        foreach (Der::extensions($der) as $oid => $extension) {
            if ($extension['critical'] && ! in_array($oid, self::UNDERSTOOD_CRITICAL, true)) {
                throw self::invalid('A certificate has a critical extension that the verifier does not check.');
            }
        }
    }

    /**
     * @param  array{subject: mixed, issuer: mixed, validFrom: int, validTo: int, basicConstraints: string, keyUsage: string}  $fields
     * @param  array{subject: mixed, issuer: mixed, validFrom: int, validTo: int, basicConstraints: string, keyUsage: string}  $issuerFields
     */
    private static function checkIssuedBy(
        OpenSSLCertificate $certificate,
        array $fields,
        OpenSSLCertificate $issuer,
        array $issuerFields,
        string $name,
    ): void {
        if ($fields['issuer'] !== $issuerFields['subject']) {
            throw self::invalid("The {$name} certificate's issuer is not the next certificate's subject.");
        }

        $result = OpenSsl::quietly(static fn (): int => openssl_x509_verify($certificate, $issuer));

        if ($result !== 1) {
            throw self::invalid("The {$name} certificate's signature is not valid.");
        }
    }

    /** @return array{subject: mixed, issuer: mixed, validFrom: int, validTo: int, basicConstraints: string, keyUsage: string} */
    private static function fields(OpenSSLCertificate $certificate): array
    {
        $parsed = OpenSsl::quietly(static fn (): array|false => openssl_x509_parse($certificate));

        if (! is_array($parsed) || ! is_int($parsed['validFrom_time_t'] ?? null) || ! is_int($parsed['validTo_time_t'] ?? null)
            || ! array_key_exists('subject', $parsed) || ! array_key_exists('issuer', $parsed)) {
            throw self::invalid('A certificate cannot be parsed.');
        }

        $extensions = is_array($parsed['extensions'] ?? null) ? $parsed['extensions'] : [];

        return [
            'subject' => $parsed['subject'],
            'issuer' => $parsed['issuer'],
            'validFrom' => $parsed['validFrom_time_t'],
            'validTo' => $parsed['validTo_time_t'],
            'basicConstraints' => is_string($extensions['basicConstraints'] ?? null) ? $extensions['basicConstraints'] : '',
            'keyUsage' => is_string($extensions['keyUsage'] ?? null) ? $extensions['keyUsage'] : '',
        ];
    }

    /** @param array{basicConstraints: string} $fields */
    private static function isCa(array $fields): bool
    {
        return preg_match('/(^|,\s*)CA:TRUE(,|$)/', $fields['basicConstraints']) === 1;
    }

    /** @param array{keyUsage: string} $fields */
    private static function canSignCertificates(array $fields): bool
    {
        return in_array('Certificate Sign', array_map(trim(...), explode(',', $fields['keyUsage'])), true);
    }

    private static function invalid(string $message): VerificationException
    {
        return VerificationException::because(Failure::InvalidCertificate, $message);
    }
}
