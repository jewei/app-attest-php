<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\CategoryPolicy;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\Verifier;

/** @return array{attestation: string, keyId: string, clientDataHash: string, at: \DateTimeImmutable, appId: AppId} */
function macAttestation(): array
{
    $sample = loadSpec('third-party/arkavo-macos27-attestation.json');

    return [
        'attestation' => (string) base64_decode(specString($sample, 'attestation_object'), true),
        'keyId' => (string) base64_decode(specString($sample, 'key_id'), true),
        'clientDataHash' => (string) base64_decode(specString($sample, 'client_data_hash'), true),
        'at' => (new \DateTimeImmutable)->setTimestamp(is_int($sample['verify_at'] ?? null) ? $sample['verify_at'] : 0),
        'appId' => AppId::fromString(specString($sample, 'app_id')),
    ];
}

it('refuses a real macOS 27 attestation as an unsupported platform', function (): void {
    $sample = macAttestation();
    $verifier = new Verifier($sample['appId'], Environment::Production, CategoryPolicy::any());

    expect(failureOf(fn () => $verifier->verifyAttestation($sample['attestation'], $sample['keyId'], $sample['clientDataHash'], $sample['at'])))
        ->toBe(Failure::UnsupportedPlatform);
});
