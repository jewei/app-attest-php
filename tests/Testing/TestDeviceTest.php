<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\Testing\TestAuthority;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

it('attests a key and signs assertions that the verifier accepts', function (Environment $environment, ?ValidationCategory $category): void {
    $authority = TestAuthority::create();
    $appId = new AppId('ABCDE12345', 'com.example.app');
    $device = $authority->device($appId, $environment, $category);
    $verifier = new Verifier($appId, $environment, null, $authority->rootPem());
    $challenge = random_bytes(32);

    $key = $verifier->verifyAttestation($device->attest(hash('sha256', $challenge, true)), $device->keyId, hash('sha256', $challenge, true));
    $first = $verifier->verifyAssertion($device->assert('GET /one'), 'GET /one', $key->publicKey, 0, $key->environment);
    $second = $verifier->verifyAssertion($device->assert('GET /two'), 'GET /two', $key->publicKey, $first->counter, $key->environment);

    expect($key->keyId)->toBe($device->keyId)
        ->and($key->validationCategory)->toBe($category)
        ->and($first->counter)->toBe(1)
        ->and($second->counter)->toBe(2)
        ->and($device->counter())->toBe(2)
        ->and($second->validationCategory)->toBe($category);
})->with([
    'production, development build' => [Environment::Production, ValidationCategory::Development],
    'production, TestFlight' => [Environment::Production, ValidationCategory::TestFlight],
    'development, no extensions' => [Environment::Development, null],
]);

it('is refused by a verifier that trusts Apple\'s root', function (): void {
    $appId = new AppId('ABCDE12345', 'com.example.app');
    $device = TestAuthority::create()->device($appId);
    $attestation = $device->attest(hash('sha256', 'challenge', true));

    expect(failureOf(fn () => (new Verifier($appId, Environment::Production, null))->verifyAttestation($attestation, $device->keyId, hash('sha256', 'challenge', true))))
        ->toBe(Failure::InvalidCertificate);
});

it('refuses a replayed assertion because the counter does not increase', function (): void {
    $authority = TestAuthority::create();
    $appId = new AppId('ABCDE12345', 'com.example.app');
    $device = $authority->device($appId);
    $verifier = new Verifier($appId, Environment::Production, null, $authority->rootPem());
    $key = $verifier->verifyAttestation($device->attest(hash('sha256', 'c', true)), $device->keyId, hash('sha256', 'c', true));
    $assertion = $device->assert('GET /me');
    $counter = $verifier->verifyAssertion($assertion, 'GET /me', $key->publicKey, 0, Environment::Production)->counter;

    expect(failureOf(fn () => $verifier->verifyAssertion($assertion, 'GET /me', $key->publicKey, $counter, Environment::Production)))
        ->toBe(Failure::CounterNotIncreased);
});
