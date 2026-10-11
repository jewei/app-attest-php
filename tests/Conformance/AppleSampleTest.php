<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\CategoryPolicy;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

it('verifies Apple\'s sample attestation with the pinned root', function (): void {
    $sample = appleSample();
    $key = $sample['verifier']->verifyAttestation($sample['attestation'], $sample['keyId'], $sample['clientDataHash'], $sample['at']);

    expect(base64_encode($key->keyId))->toBe(specString($sample['expected'], 'credentialId'))
        ->and($key->environment)->toBe(Environment::Production)
        ->and($key->validationCategory)->toBe(ValidationCategory::OperatingSystem)
        ->and($key->bundleVersion)->toBe(specString($sample['expected'], 'bundleVersion'))
        ->and($key->receipt)->not->toBe('')
        ->and($key->publicKey)->toStartWith('-----BEGIN PUBLIC KEY-----');

    // The credential certificate that the receipt's field 3 must equal: its key is the attested key.
    $pem = "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($key->certificate), 64, "\n")."-----END CERTIFICATE-----\n";
    $details = openssl_pkey_get_details(openssl_pkey_get_public($pem) ?: throw new \RuntimeException('No key.'));

    expect(is_array($details) ? $details['key'] ?? null : null)->toBe($key->publicKey);
});

it('derives the key ID from the X9.62 uncompressed point of the sample key', function (): void {
    $sample = appleSample();
    $key = $sample['verifier']->verifyAttestation($sample['attestation'], $sample['keyId'], $sample['clientDataHash'], $sample['at']);
    $details = openssl_pkey_get_details(openssl_pkey_get_public($key->publicKey) ?: throw new \RuntimeException('No key.'));
    $ec = is_array($details) && is_array($details['ec'] ?? null) ? $details['ec'] : [];
    $x = is_string($ec['x'] ?? null) ? $ec['x'] : '';
    $y = is_string($ec['y'] ?? null) ? $ec['y'] : '';
    $point = "\x04".str_pad($x, 32, "\0", STR_PAD_LEFT).str_pad($y, 32, "\0", STR_PAD_LEFT);

    expect(hash('sha256', $point, true))->toBe($sample['keyId']);
});

it('refuses the sample now, because its credential certificate expired on 2026-04-23', function (): void {
    $sample = appleSample();

    expect(failureOf(fn () => $sample['verifier']->verifyAttestation($sample['attestation'], $sample['keyId'], $sample['clientDataHash'])))
        ->toBe(Failure::InvalidCertificate);
});

it('refuses the sample for each wrong input', function (string $case, Failure $failure): void {
    $sample = appleSample();
    $verifier = $sample['verifier'];
    $keyId = $sample['keyId'];
    $clientDataHash = $sample['clientDataHash'];

    match ($case) {
        'challenge' => $clientDataHash = hash('sha256', $clientDataHash, true),
        'key ID' => $keyId[0] = chr(ord($keyId[0]) ^ 1),
        'App ID' => $verifier = new Verifier(new AppId('1234567890', 'com.example.other'), Environment::Production, CategoryPolicy::any()),
        'environment' => $verifier = new Verifier(new AppId('1234567890', 'com.example.myapp'), Environment::Development, CategoryPolicy::any()),
        'category' => $verifier = new Verifier(new AppId('1234567890', 'com.example.myapp'), Environment::Production, CategoryPolicy::only(ValidationCategory::AppStore)),
        default => throw new \LogicException($case),
    };

    expect(failureOf(fn () => $verifier->verifyAttestation($sample['attestation'], $keyId, $clientDataHash, $sample['at'])))->toBe($failure);
})->with([
    ['challenge', Failure::NonceMismatch],
    ['key ID', Failure::KeyIdMismatch],
    ['App ID', Failure::AppIdMismatch],
    ['environment', Failure::EnvironmentMismatch],
    ['category', Failure::CategoryNotAllowed],
]);

it('refuses the sample under a different trust anchor', function (): void {
    $sample = appleSample();
    $verifier = testVerifier(appId: new AppId('1234567890', 'com.example.myapp'));

    expect(failureOf(fn () => $verifier->verifyAttestation($sample['attestation'], $sample['keyId'], $sample['clientDataHash'], $sample['at'])))
        ->toBe(Failure::InvalidCertificate);
});

it('accepts the sample from the first to the last second of its credential certificate', function (string $at, ?Failure $failure): void {
    $sample = appleSample();

    expect(failureOf(fn () => $sample['verifier']->verifyAttestation($sample['attestation'], $sample['keyId'], $sample['clientDataHash'], new \DateTimeImmutable($at))))
        ->toBe($failure);
})->with([
    'one second before notBefore' => ['2026-04-20T18:13:11Z', Failure::InvalidCertificate],
    'notBefore' => ['2026-04-20T18:13:12Z', null],
    'notAfter' => ['2026-04-23T18:13:12Z', null],
    'one second after notAfter' => ['2026-04-23T18:13:13Z', Failure::InvalidCertificate],
]);
