<?php

declare(strict_types=1);

namespace AppAttest\Internal;

use OpenSSLCertificate;

/**
 * @internal A checked trust anchor: the OpenSSL certificate and its fields.
 *
 * @phpstan-import-type Certificate from Der
 */
final readonly class TrustAnchor
{
    /** @param Certificate $fields */
    public function __construct(
        public OpenSSLCertificate $certificate,
        public array $fields,
    ) {}
}
