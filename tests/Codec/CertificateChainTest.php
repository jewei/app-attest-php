<?php

declare(strict_types=1);

use AppAttest\Exception\Failure;
use AppAttest\Internal\CertificateChain;
use AppAttest\Internal\Der;
use AppAttest\Internal\TrustAnchor;
use AppAttest\Tests\Support\TestAuthority;

// Verifier::credentialKey() checks the curve again, so only a direct call proves the chain check itself.
it('refuses a credential key that is not P-256 in the chain check', function (string $curve, ?Failure $failure): void {
    $authority = TestAuthority::shared();
    $root = openssl_x509_read($authority->rootPem);
    $anchor = new TrustAnchor($root === false ? throw new \RuntimeException('root') : $root, Der::certificate($authority->rootDer));
    $credential = $authority->attest(testAppId(), testClientDataHash(), ['curve' => $curve])['credential'];

    expect(failureOf(fn () => CertificateChain::verify($credential, $authority->intermediateDer, $anchor, new \DateTimeImmutable)))->toBe($failure);
})->with([
    'P-256' => ['prime256v1', null],
    'P-384' => ['secp384r1', Failure::InvalidCertificate],
]);
