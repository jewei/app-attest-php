<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\CategoryPolicy;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

/**
 * The real iOS 27.0.1 capture: a development-signed app, a new key that never enrolled, an attestation, and two
 * assertions with counters 1 and 2.
 *
 * @return array{appId: AppId, attestation: string, keyId: string, clientDataHash: string, at: \DateTimeImmutable, bundleVersion: string, assertions: list<array{clientData: string, assertion: string}>}
 */
function realIosCapture(): array
{
    $fixture = loadSpec('termakan-ios27-attestation.json');
    $items = $fixture['assertions'] ?? null;
    $assertions = [];

    foreach (is_array($items) ? $items : [] as $item) {
        $item = stringKeyed(is_array($item) ? $item : [], 'assertions');
        $assertions[] = [
            'clientData' => specString($item, 'clientData'),
            'assertion' => (string) base64_decode(specString($item, 'assertion'), true),
        ];
    }

    return [
        'appId' => AppId::fromString(specString($fixture, 'appId')),
        'attestation' => (string) base64_decode(specString($fixture, 'attestation'), true),
        'keyId' => (string) base64_decode(specString($fixture, 'keyId'), true),
        // The exact clientDataHash bytes: SHA-256 of the challenge text, as the app passed them to attestKey().
        'clientDataHash' => hash('sha256', specString($fixture, 'challenge'), true),
        'at' => new \DateTimeImmutable(specString($fixture, 'captured')),
        'bundleVersion' => specString($fixture, 'bundleVersion'),
        'assertions' => $assertions,
    ];
}

it('records the hash of the challenge that the app attested', function (): void {
    $fixture = loadSpec('termakan-ios27-attestation.json');

    expect(base64_encode(realIosCapture()['clientDataHash']))->toBe(specString($fixture, 'clientDataHashBase64'));
});

it('records two assertions', function (): void {
    expect(realIosCapture()['assertions'])->toHaveCount(2);
});

it('verifies a real iOS 27.0.1 attestation of a development-signed app', function (): void {
    $capture = realIosCapture();
    $verifier = new Verifier($capture['appId'], Environment::Production, CategoryPolicy::only(ValidationCategory::Development));

    $key = $verifier->verifyAttestation($capture['attestation'], $capture['keyId'], $capture['clientDataHash'], $capture['at']);

    expect($key->keyId)->toBe($capture['keyId'])
        ->and($key->environment)->toBe(Environment::Production)
        ->and($key->validationCategory)->toBe(ValidationCategory::Development)
        // Apple writes CFBundleVersion (the build number "1"), not CFBundleShortVersionString ("0.1.0").
        ->and($key->bundleVersion)->toBe($capture['bundleVersion'])
        ->and($key->bundleVersion)->toBe('1')
        ->and($key->receipt)->not->toBe('');
});

it('verifies the two real assertions in order with the attested key', function (): void {
    $capture = realIosCapture();
    $verifier = new Verifier($capture['appId'], Environment::Production, CategoryPolicy::only(ValidationCategory::Development));
    $publicKey = $verifier->verifyAttestation($capture['attestation'], $capture['keyId'], $capture['clientDataHash'], $capture['at'])->publicKey;
    $previous = 0;

    foreach ($capture['assertions'] as $index => $item) {
        $verified = $verifier->verifyAssertion($item['assertion'], $item['clientData'], $publicKey, $previous, Environment::Production);

        expect($verified->counter)->toBe($index + 1)
            ->and($verified->validationCategory)->toBe(ValidationCategory::Development)
            ->and($verified->bundleVersion)->toBe('1');
        $previous = $verified->counter;
    }
});

it('refuses the real attestation for each wrong input', function (string $case, Failure $failure): void {
    $capture = realIosCapture();
    $verifier = new Verifier($capture['appId'], Environment::Production, CategoryPolicy::any());
    $keyId = $capture['keyId'];
    $clientDataHash = $capture['clientDataHash'];
    $at = $capture['at'];

    match ($case) {
        'challenge' => $clientDataHash = hash('sha256', 'another challenge', true),
        'challenge text instead of its hash' => $clientDataHash = specString(loadSpec('termakan-ios27-attestation.json'), 'challenge'),
        'key ID' => $keyId[0] = chr(ord($keyId[0]) ^ 1),
        'App ID' => $verifier = new Verifier(new AppId('4L4SS26L9J', 'com.jewei.other'), Environment::Production, CategoryPolicy::any()),
        'environment' => $verifier = new Verifier($capture['appId'], Environment::Development, CategoryPolicy::any()),
        'distribution only' => $verifier = new Verifier($capture['appId'], Environment::Production, CategoryPolicy::onlyOrMissing(ValidationCategory::AppStore, ValidationCategory::TestFlight)),
        // The credential certificate is valid from 2026-10-11T06:20:12Z to 2026-10-14T06:20:12Z.
        'before the certificate' => $at = new \DateTimeImmutable('2026-10-11T06:20:11Z'),
        'after the certificate' => $at = new \DateTimeImmutable('2026-10-14T06:20:13Z'),
        default => throw new \LogicException($case),
    };

    expect(failureOf(fn () => $verifier->verifyAttestation($capture['attestation'], $keyId, $clientDataHash, $at)))->toBe($failure);
})->with([
    ['challenge', Failure::NonceMismatch],
    ['challenge text instead of its hash', Failure::NonceMismatch],
    ['key ID', Failure::KeyIdMismatch],
    ['App ID', Failure::AppIdMismatch],
    ['environment', Failure::EnvironmentMismatch],
    ['distribution only', Failure::CategoryNotAllowed],
    ['before the certificate', Failure::InvalidCertificate],
    ['after the certificate', Failure::InvalidCertificate],
]);

it('refuses the real assertions when anything differs', function (string $case, Failure $failure): void {
    $capture = realIosCapture();
    $verifier = new Verifier($capture['appId'], Environment::Production, CategoryPolicy::any());
    $publicKey = $verifier->verifyAttestation($capture['attestation'], $capture['keyId'], $capture['clientDataHash'], $capture['at'])->publicKey;
    [$first, $second] = $capture['assertions'];
    $assertion = $second['assertion'];
    $clientData = $second['clientData'];
    $previous = 1;

    match ($case) {
        'replayed' => [$assertion, $clientData, $previous] = [$first['assertion'], $first['clientData'], 1],
        'counter already seen' => $previous = 2,
        'older after newer' => [$assertion, $clientData, $previous] = [$first['assertion'], $first['clientData'], 2],
        'client data of the other assertion' => $clientData = $first['clientData'],
        'another key' => $publicKey = attestedKey()['publicKey'],
        'App ID' => $verifier = new Verifier(new AppId('4L4SS26L9J', 'com.jewei.other'), Environment::Production, CategoryPolicy::any()),
        'distribution only' => $verifier = new Verifier($capture['appId'], Environment::Production, CategoryPolicy::onlyOrMissing(ValidationCategory::AppStore, ValidationCategory::TestFlight)),
        default => throw new \LogicException($case),
    };

    expect(failureOf(fn () => $verifier->verifyAssertion($assertion, $clientData, $publicKey, $previous, Environment::Production)))->toBe($failure);
})->with([
    ['replayed', Failure::CounterNotIncreased],
    ['counter already seen', Failure::CounterNotIncreased],
    ['older after newer', Failure::CounterNotIncreased],
    ['client data of the other assertion', Failure::InvalidSignature],
    ['another key', Failure::InvalidSignature],
    ['App ID', Failure::AppIdMismatch],
    ['distribution only', Failure::CategoryNotAllowed],
]);
