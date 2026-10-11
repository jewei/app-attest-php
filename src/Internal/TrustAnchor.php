<?php

declare(strict_types=1);

namespace AppAttest\Internal;

use OpenSSLCertificate;

/**
 * @internal A checked trust anchor: the OpenSSL certificate, its DER, and its fields.
 *
 * @phpstan-import-type Extension from Der
 */
final readonly class TrustAnchor
{
    /** @param array{issuer: string, subject: string, notBefore: int, notAfter: int, extensions: list<Extension>} $fields */
    public function __construct(
        public OpenSSLCertificate $certificate,
        public string $der,
        public array $fields,
    ) {}
}
