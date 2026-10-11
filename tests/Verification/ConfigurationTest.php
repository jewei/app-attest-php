<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;
use AppAttest\Tests\Support\TestAuthority;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

it('builds the App ID from the prefix and the bundle ID', function (): void {
    $appId = new AppId('ABCDE12345', 'com.example.app');

    expect((string) $appId)->toBe('ABCDE12345.com.example.app')
        ->and($appId->hash())->toBe(hash('sha256', 'ABCDE12345.com.example.app', true))
        ->and(AppId::fromString('ABCDE12345.com.example.app'))->toEqual($appId)
        ->and((string) new AppId('1234567890', 'app'))->toBe('1234567890.app');
});

it('refuses an App ID prefix that is not 10 uppercase letters or digits', function (string $prefix): void {
    expect(fn () => new AppId($prefix, 'com.example.app'))->toThrow(\InvalidArgumentException::class);
})->with(['', 'ABCDE1234', 'ABCDE123456', 'abcde12345', 'ABCDE 1234', "ABCDE12345\n"]);

it('refuses a bundle ID with other characters', function (string $bundleId): void {
    expect(fn () => new AppId('ABCDE12345', $bundleId))->toThrow(\InvalidArgumentException::class);
})->with(['', '.com.example', 'com.example.', 'com..example', 'com.exa mple', 'com.example_app', "com.example\n", str_repeat('a', 256)]);

it('accepts a bundle ID of 255 characters', function (): void {
    expect((new AppId('ABCDE12345', str_repeat('a', 255)))->bundleId)->toHaveLength(255);
});

it('refuses an App ID string without a period', function (): void {
    expect(fn () => AppId::fromString('ABCDE12345'))->toThrow(\InvalidArgumentException::class);
});

it('names the AAGUID of each environment', function (): void {
    expect(Environment::Production->aaguid())->toBe("appattest\0\0\0\0\0\0\0")->toHaveLength(16)
        ->and(Environment::Development->aaguid())->toBe('appattestdevelop')->toHaveLength(16);
});

it('uses the pinned Apple root by default', function (): void {
    $attestation = testAttestation();
    $verifier = new Verifier(testAppId(), Environment::Production);

    expect(failureOf(fn () => $verifier->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash())))
        ->toBe(Failure::InvalidCertificate);
});

it('refuses an empty or mixed category list', function (array $categories): void {
    // Reflection passes the wrong types that a caller without static analysis could pass.
    expect(fn () => (new \ReflectionClass(Verifier::class))->newInstance(testAppId(), Environment::Production, $categories))
        ->toThrow(\InvalidArgumentException::class);
})->with([
    'empty' => [[]],
    'not a list' => [['a' => ValidationCategory::AppStore]],
    'an integer' => [[ValidationCategory::AppStore, 4]],
]);

it('refuses a trust anchor that is not a CA certificate PEM', function (string $anchor): void {
    expect(fn () => new Verifier(testAppId(), Environment::Production, trustAnchor: $anchor))->toThrow(\InvalidArgumentException::class);
})->with([
    'empty' => [''],
    'file path' => ['file://'.__DIR__.'/../../resources/apple-app-attestation-root-ca.pem'],
    'public key' => [TestAuthority::publicPem(TestAuthority::key())],
    'bad PEM' => ["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"],
    'end-entity certificate' => [(static function (): string {
        $credential = testAttestation()['credential'];

        return "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($credential), 64, "\n")."-----END CERTIFICATE-----\n";
    })()],
]);

it('keeps VerificationException construction internal', function (): void {
    $constructor = new \ReflectionMethod(VerificationException::class, '__construct');

    expect($constructor->isPrivate())->toBeTrue()
        ->and(VerificationException::because(Failure::NonceMismatch, 'message')->failure)->toBe(Failure::NonceMismatch);
});

it('keeps the failure codes stable', function (): void {
    expect(array_map(static fn (Failure $failure): string => $failure->value, Failure::cases()))->toBe([
        'malformed_input', 'unsupported_format', 'invalid_certificate', 'nonce_mismatch', 'key_id_mismatch',
        'app_id_mismatch', 'non_zero_counter', 'environment_mismatch', 'credential_id_mismatch',
        'category_not_allowed', 'invalid_signature', 'counter_not_increased',
    ]);
});

it('names Apple\'s validation categories', function (): void {
    expect(array_map(static fn (ValidationCategory $category): int => $category->value, ValidationCategory::cases()))
        ->toBe([1, 2, 3, 4, 5, 6, 10]);
});

it('leaves no PHP error behind when OpenSSL refuses input', function (): void {
    error_clear_last();

    expect(fn () => new Verifier(testAppId(), Environment::Production, trustAnchor: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
        ->toThrow(\InvalidArgumentException::class)
        ->and(error_get_last())->toBeNull();
});
