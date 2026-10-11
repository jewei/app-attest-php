<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\CategoryPolicy;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

/** @return array{attestation: string, keyId: string, clientDataHash: string, at: \DateTimeImmutable, appId: AppId} */
function appleSample2024(): array
{
    $sample = loadSpec('apple-sample-attestation-2024.json');

    return [
        'attestation' => (string) base64_decode(specString($sample, 'attestation'), true),
        'keyId' => (string) base64_decode(specString($sample, 'keyId'), true),
        'clientDataHash' => specString($sample, 'clientDataHash'),
        'at' => new \DateTimeImmutable(specString($sample, 'checkTime')),
        'appId' => new AppId(specString($sample, 'appIdPrefix'), specString($sample, 'bundleId')),
    ];
}

it('verifies Apple\'s 2024 sample (iOS 18.0, no extensions) with onlyOrMissing()', function (): void {
    $sample = appleSample2024();
    $verifier = new Verifier($sample['appId'], Environment::Production, CategoryPolicy::onlyOrMissing(ValidationCategory::AppStore));

    $key = $verifier->verifyAttestation($sample['attestation'], $sample['keyId'], $sample['clientDataHash'], $sample['at']);

    expect($key->keyId)->toBe($sample['keyId'])
        ->and($key->validationCategory)->toBeNull()
        ->and($key->bundleVersion)->toBeNull()
        ->and($key->environment)->toBe(Environment::Production);
});

it('refuses Apple\'s 2024 sample with only(), because iOS 18.0 writes no category', function (): void {
    $sample = appleSample2024();
    $verifier = new Verifier($sample['appId'], Environment::Production, CategoryPolicy::only(ValidationCategory::AppStore));

    expect(failureOf(fn () => $verifier->verifyAttestation($sample['attestation'], $sample['keyId'], $sample['clientDataHash'], $sample['at'])))
        ->toBe(Failure::CategoryNotAllowed);
});

it('refuses Apple\'s 2024 sample for each wrong input', function (string $case, Failure $failure): void {
    $sample = appleSample2024();
    $verifier = new Verifier($sample['appId'], Environment::Production, CategoryPolicy::any());
    $keyId = $sample['keyId'];
    $clientDataHash = $sample['clientDataHash'];
    $at = $sample['at'];

    match ($case) {
        'challenge' => $clientDataHash = 'another_server_challenge',
        'key ID' => $keyId[0] = chr(ord($keyId[0]) ^ 1),
        'App ID' => $verifier = new Verifier(new AppId('0352187391', 'com.apple.other'), Environment::Production, CategoryPolicy::any()),
        'environment' => $verifier = new Verifier($sample['appId'], Environment::Development, CategoryPolicy::any()),
        'time' => $at = new \DateTimeImmutable('2024-04-21T00:00:00Z'),
        default => throw new \LogicException($case),
    };

    expect(failureOf(fn () => $verifier->verifyAttestation($sample['attestation'], $keyId, $clientDataHash, $at)))->toBe($failure);
})->with([
    ['challenge', Failure::NonceMismatch],
    ['key ID', Failure::KeyIdMismatch],
    ['App ID', Failure::AppIdMismatch],
    ['environment', Failure::EnvironmentMismatch],
    ['time', Failure::InvalidCertificate],
]);
