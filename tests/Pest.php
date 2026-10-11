<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;
use AppAttest\Tests\Support\TestAuthority;
use AppAttest\Verifier;

function testAppId(): AppId
{
    return new AppId('ABCDE12345', 'com.example.app');
}

function testClientDataHash(): string
{
    return hash('sha256', 'one-time challenge', true);
}

/** @param array<mixed>|null $categories */
function testVerifier(
    Environment $environment = Environment::Production,
    ?array $categories = null,
    ?AppId $appId = null,
    ?TestAuthority $authority = null,
): Verifier {
    return new Verifier($appId ?? testAppId(), $environment, $categories, ($authority ?? TestAuthority::shared())->rootPem);
}

/**
 * @param  array<mixed>  $options  TestAuthority::attest() options.
 * @return array{attestation: string, keyId: string, key: \OpenSSLAsymmetricKey, publicKey: string, credential: string}
 */
function testAttestation(array $options = []): array
{
    return TestAuthority::shared()->attest(testAppId(), testClientDataHash(), $options);
}

/** Returns the failure that the call threw, or null when it returned. */
function failureOf(\Closure $call): ?Failure
{
    try {
        $call();
    } catch (VerificationException $exception) {
        return $exception->failure;
    }

    return null;
}

/** @param array<mixed> $options TestAuthority::attest() options. */
function attestationFailure(array $options = [], ?Verifier $verifier = null, ?\DateTimeInterface $at = null): ?Failure
{
    $attestation = testAttestation($options);

    return failureOf(fn () => ($verifier ?? testVerifier())->verifyAttestation(
        $attestation['attestation'],
        $attestation['keyId'],
        testClientDataHash(),
        $at,
    ));
}

/** @return array<string, mixed> */
function loadSpec(string $file): array
{
    $json = file_get_contents(__DIR__.'/../spec/'.$file);

    if ($json === false) {
        throw new \RuntimeException("Unable to read spec file: {$file}");
    }

    $data = json_decode($json, true, flags: JSON_THROW_ON_ERROR);

    if (! is_array($data)) {
        throw new \RuntimeException("The spec file is not a JSON object: {$file}");
    }

    return stringKeyed($data, $file);
}

/** @param array<string, mixed> $data */
function specString(array $data, string $field): string
{
    $value = $data[$field] ?? null;

    if (! is_string($value)) {
        throw new \RuntimeException("The spec field is not a string: {$field}");
    }

    return $value;
}

/**
 * @param  array<string, mixed>  $data
 * @return array<string, mixed>
 */
function specObject(array $data, string $field): array
{
    $value = $data[$field] ?? null;

    if (! is_array($value)) {
        throw new \RuntimeException("The spec field is not an object: {$field}");
    }

    return stringKeyed($value, $field);
}

/**
 * @param  array<mixed>  $data
 * @return array<string, mixed>
 */
function stringKeyed(array $data, string $name): array
{
    $keyed = [];

    foreach ($data as $key => $value) {
        if (! is_string($key)) {
            throw new \RuntimeException("The spec object has a key that is not a string: {$name}");
        }

        $keyed[$key] = $value;
    }

    return $keyed;
}

/** @return array{verifier: Verifier, attestation: string, keyId: string, clientDataHash: string, at: \DateTimeImmutable, expected: array<string, mixed>} */
function appleSample(): array
{
    $sample = loadSpec('apple-sample-attestation.json');

    return [
        'verifier' => new Verifier(new AppId(specString($sample, 'appIdPrefix'), specString($sample, 'bundleId')), Environment::Production),
        'attestation' => (string) base64_decode(specString($sample, 'attestation'), true),
        'keyId' => (string) base64_decode(specString($sample, 'keyId'), true),
        'clientDataHash' => specString($sample, 'clientDataHash'),
        'at' => new \DateTimeImmutable(specString($sample, 'checkTime')),
        'expected' => specObject($sample, 'expected'),
    ];
}

/** @return array{key: \OpenSSLAsymmetricKey, publicKey: string} An attested key. */
function attestedKey(): array
{
    $attestation = testAttestation();
    $verified = testVerifier()->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash());

    return ['key' => $attestation['key'], 'publicKey' => $verified->publicKey];
}

/** @param array<mixed> $options TestAuthority::assertion() options. */
function assertionFailure(int $counter = 1, int $previous = 0, array $options = [], string $clientData = 'POST /orders', ?Verifier $verifier = null, ?string $verifyClientData = null): ?Failure
{
    $key = attestedKey();
    $assertion = TestAuthority::assertion($key['key'], testAppId(), $clientData, $counter, $options);

    return failureOf(fn () => ($verifier ?? testVerifier())->verifyAssertion($assertion, $verifyClientData ?? $clientData, $key['publicKey'], $previous));
}
