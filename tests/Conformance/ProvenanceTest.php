<?php

declare(strict_types=1);

it('pins the Apple App Attestation Root CA recorded in the provenance file', function (): void {
    $provenance = specObject(loadSpec('provenance.json'), 'apple-app-attestation-root-ca.pem');
    $pem = (string) file_get_contents(__DIR__.'/../../resources/apple-app-attestation-root-ca.pem');
    $certificate = openssl_x509_read($pem) ?: throw new \RuntimeException('The pinned root cannot be read.');
    $parsed = openssl_x509_parse($certificate) ?: throw new \RuntimeException('The pinned root cannot be parsed.');
    $subject = is_array($parsed['subject'] ?? null) ? $parsed['subject'] : [];

    expect(hash('sha256', $pem))->toBe(specString($provenance, 'sha256'))
        ->and(openssl_x509_fingerprint($certificate, 'sha256'))->toBe(specString($provenance, 'certificateSha256'))
        ->and($subject['CN'] ?? null)->toBe('Apple App Attestation Root CA')
        ->and($parsed['issuer'] ?? null)->toBe($subject)
        ->and($parsed['validTo_time_t'] ?? null)->toBe(2373148800);
});

it('records the hash of Apple\'s sample attestation', function (): void {
    $provenance = specObject(loadSpec('provenance.json'), 'apple-sample-attestation.json');
    $attestation = (string) base64_decode(specString(loadSpec('apple-sample-attestation.json'), 'attestation'), true);

    expect(hash('sha256', $attestation))->toBe(specString($provenance, 'attestationSha256'));
});

it('records the hash of the third-party assertion fixture', function (): void {
    $provenance = specObject(loadSpec('provenance.json'), 'third-party/block-buzz-ios27-assertion.json');
    $file = (string) file_get_contents(__DIR__.'/../../spec/third-party/block-buzz-ios27-assertion.json');

    expect(hash('sha256', $file))->toBe(specString($provenance, 'sha256'))
        ->and(is_file(__DIR__.'/../../spec/third-party/LICENSE-block-buzz'))->toBeTrue();
});

it('records the hash of Apple\'s 2024 sample attestation', function (): void {
    $provenance = specObject(loadSpec('provenance.json'), 'apple-sample-attestation-2024.json');
    $attestation = (string) base64_decode(specString(loadSpec('apple-sample-attestation-2024.json'), 'attestation'), true);

    expect(hash('sha256', $attestation))->toBe(specString($provenance, 'attestationSha256'));
});

it('records the hash of the third-party macOS attestation fixture', function (): void {
    $provenance = specObject(loadSpec('provenance.json'), 'third-party/arkavo-macos27-attestation.json');
    $file = (string) file_get_contents(__DIR__.'/../../spec/third-party/arkavo-macos27-attestation.json');

    expect(hash('sha256', $file))->toBe(specString($provenance, 'sha256'))
        ->and(is_file(__DIR__.'/../../spec/third-party/LICENSE-arkavo'))->toBeTrue();
});
