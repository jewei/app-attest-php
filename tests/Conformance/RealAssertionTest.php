<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

/** @return array{appId: AppId, assertion: string, clientData: string, publicKey: string, previous: int, counter: int} */
function realAssertion(): array
{
    $fixture = loadSpec('third-party/block-buzz-ios27-assertion.json');
    $point = (string) hex2bin(specString($fixture, 'public_key_hex'));
    // SubjectPublicKeyInfo for an EC P-256 key: the fixed DER prefix, then the X9.62 point.
    $spki = (string) hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200').$point;
    $previous = $fixture['previous_counter'] ?? null;
    $counter = $fixture['expected_counter'] ?? null;

    if (! is_int($previous) || ! is_int($counter)) {
        throw new \RuntimeException('The fixture counters are not integers.');
    }

    return [
        'appId' => AppId::fromString(specString($fixture, 'app_id')),
        'assertion' => (string) base64_decode(specString($fixture, 'assertion_b64'), true),
        'clientData' => specString($fixture, 'client_data'),
        'publicKey' => "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($spki), 64, "\n")."-----END PUBLIC KEY-----\n",
        'previous' => $previous,
        'counter' => $counter,
    ];
}

it('verifies a real iOS 27 assertion with Apple\'s extensions', function (): void {
    $fixture = realAssertion();
    $verifier = new Verifier($fixture['appId'], Environment::Production, [ValidationCategory::TestFlight]);
    $verified = $verifier->verifyAssertion($fixture['assertion'], $fixture['clientData'], $fixture['publicKey'], $fixture['previous'], Environment::Production);

    expect($verified->counter)->toBe($fixture['counter'])
        ->and($verified->validationCategory)->toBe(ValidationCategory::TestFlight)
        ->and($verified->bundleVersion)->toBe('2');
});

it('refuses the real assertion when anything differs', function (string $case, Failure $failure): void {
    $fixture = realAssertion();
    $verifier = new Verifier($fixture['appId'], Environment::Production);
    $clientData = $fixture['clientData'];
    $previous = $fixture['previous'];

    match ($case) {
        'replayed' => $previous = $fixture['counter'],
        'client data' => $clientData .= ' ',
        'App ID' => $verifier = new Verifier(new AppId('6PU678XRWJ', 'com.example.other'), Environment::Production),
        'App Store only' => $verifier = new Verifier($fixture['appId'], Environment::Production, [ValidationCategory::AppStore]),
        default => throw new \LogicException($case),
    };

    expect(failureOf(fn () => $verifier->verifyAssertion($fixture['assertion'], $clientData, $fixture['publicKey'], $previous, Environment::Production)))->toBe($failure);
})->with([
    ['replayed', Failure::CounterNotIncreased],
    ['client data', Failure::InvalidSignature],
    ['App ID', Failure::AppIdMismatch],
    ['App Store only', Failure::CategoryNotAllowed],
]);
