<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Exception\Failure;
use AppAttest\Tests\Support\AssertionObject;
use AppAttest\Tests\Support\Bytes;
use AppAttest\Tests\Support\TestAuthority;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

it('accepts a valid assertion and returns the new counter', function (): void {
    $key = attestedKey();
    $assertion = TestAuthority::assertion($key['key'], testAppId(), 'POST /orders', 5);
    $verified = testVerifier()->verifyAssertion($assertion, 'POST /orders', $key['publicKey'], 4);

    expect($verified->counter)->toBe(5)
        ->and($verified->validationCategory)->toBe(ValidationCategory::TestFlight)
        ->and($verified->bundleVersion)->toBe('1.0');
});

it('accepts counters at the edges of the 32-bit range', function (int $counter, int $previous): void {
    expect(assertionFailure($counter, $previous))->toBeNull();
})->with([
    'first assertion' => [1, 0],
    'largest counter' => [0xFFFFFFFF, 0xFFFFFFFE],
    'a jump' => [1000, 3],
]);

it('refuses a counter that does not increase', function (int $counter, int $previous): void {
    expect(assertionFailure($counter, $previous))->toBe(Failure::CounterNotIncreased);
})->with([
    'zero' => [0, 0],
    'replayed' => [7, 7],
    'older' => [6, 7],
    'after the largest counter' => [0xFFFFFFFF, 0xFFFFFFFF],
]);

it('refuses other client data', function (): void {
    expect(assertionFailure(verifyClientData: 'POST /orders?amount=1000'))->toBe(Failure::InvalidSignature)
        ->and(assertionFailure(verifyClientData: ''))->toBe(Failure::InvalidSignature);
});

it('accepts empty client data when the app signed empty client data', function (): void {
    expect(assertionFailure(clientData: ''))->toBeNull();
});

it('refuses a signature from another key', function (): void {
    expect(assertionFailure(options: ['signWith' => TestAuthority::key()]))->toBe(Failure::InvalidSignature);
});

it('refuses a signature that is not ECDSA DER over the nonce', function (string $signature): void {
    expect(assertionFailure(options: ['signature' => $signature]))->toBe(Failure::InvalidSignature);
})->with([
    'empty' => [''],
    'junk' => ['junk'],
    'raw 64 bytes' => [str_repeat("\x01", 64)],
    'empty DER sequence' => ["\x30\x00"],
]);

it('refuses a signature over authenticatorData || clientDataHash, one hash short', function (): void {
    $key = attestedKey();
    $authenticatorData = testAppId()->hash()."\x00".pack('N', 1);
    openssl_sign($authenticatorData.hash('sha256', 'POST /orders', true), $signature, $key['key'], OPENSSL_ALGO_SHA256);
    if (! is_string($signature)) {
        throw new \RuntimeException('openssl_sign failed.');
    }

    $assertion = \AppAttest\Tests\Support\CborEncoder::encode(['signature' => new Bytes($signature), 'authenticatorData' => new Bytes($authenticatorData)]);

    expect(failureOf(fn () => testVerifier()->verifyAssertion($assertion, 'POST /orders', $key['publicKey'], 0)))->toBe(Failure::InvalidSignature);
});

it('refuses authenticator data that changed after signing', function (): void {
    $mutate = static function (AssertionObject $object): void {
        $data = $object->authenticatorDataBytes();
        $data[36] = chr(ord($data[36]) + 1);
        $object->authenticatorData = new Bytes($data);
    };

    expect(assertionFailure(options: ['mutate' => $mutate]))->toBe(Failure::InvalidSignature);
});

it('refuses another App ID', function (): void {
    expect(assertionFailure(options: ['rpIdHash' => (new AppId('ABCDE12345', 'com.example.other'))->hash()]))->toBe(Failure::AppIdMismatch)
        ->and(assertionFailure(verifier: testVerifier(appId: new AppId('ABCDE12345', 'com.example.other'))))->toBe(Failure::AppIdMismatch);
});

it('applies the validation category policy', function (): void {
    expect(assertionFailure(verifier: testVerifier(categories: [ValidationCategory::AppStore])))->toBe(Failure::CategoryNotAllowed)
        ->and(assertionFailure(verifier: testVerifier(categories: [ValidationCategory::TestFlight])))->toBeNull()
        ->and(assertionFailure(options: ['extensions' => null], verifier: testVerifier(categories: [ValidationCategory::TestFlight])))->toBe(Failure::CategoryNotAllowed)
        ->and(assertionFailure(options: ['extensions' => ['apple_validation_category_01' => new Bytes("\x08\0\0\0")]]))->toBe(Failure::CategoryNotAllowed);
});

it('accepts an assertion without extensions', function (): void {
    $key = attestedKey();
    $assertion = TestAuthority::assertion($key['key'], testAppId(), 'GET /me', 1, ['extensions' => null]);
    $verified = testVerifier()->verifyAssertion($assertion, 'GET /me', $key['publicKey'], 0);

    expect($verified->validationCategory)->toBeNull()
        ->and($verified->bundleVersion)->toBeNull();
});

it('refuses an object that is not Apple\'s structure', function (\Closure $mutate): void {
    expect(assertionFailure(options: ['mutate' => $mutate]))->toBe(Failure::MalformedInput);
})->with([
    'not a map' => [static fn (AssertionObject $object) => $object->replaceWith(1)],
    'extra field' => [static function (AssertionObject $object): void {
        $object->extraFields = ['extra' => 1];
    }],
    'missing signature' => [static function (AssertionObject $object): void {
        $object->omit = ['signature'];
    }],
    'signature as text' => [static function (AssertionObject $object): void {
        $object->signature = 'signature';
    }],
    'authenticatorData as text' => [static function (AssertionObject $object): void {
        $object->authenticatorData = 'data';
    }],
    'short authenticatorData' => [static function (AssertionObject $object): void {
        $object->authenticatorData = new Bytes(substr($object->authenticatorDataBytes(), 0, 36));
    }],
]);

it('refuses malformed extensions before the signature check', function (): void {
    expect(assertionFailure(options: ['extensions' => "\xFF"]))->toBe(Failure::MalformedInput);
});

it('refuses an empty or oversized assertion', function (string $assertion): void {
    expect(failureOf(fn () => testVerifier()->verifyAssertion($assertion, 'x', attestedKey()['publicKey'], 0)))->toBe(Failure::MalformedInput);
})->with([
    'empty' => [''],
    'one byte over the limit' => [str_repeat("\xA0", Verifier::MAX_ASSERTION_BYTES + 1)],
]);

it('refuses a stored public key that is not an EC P-256 PEM', function (string $publicKey): void {
    expect(fn () => testVerifier()->verifyAssertion("\xA0", 'x', $publicKey, 0))->toThrow(\InvalidArgumentException::class);
})->with([
    'empty' => [''],
    'file path' => ['file:///etc/hosts'],
    'certificate' => [TestAuthority::shared()->rootPem],
    'bad PEM' => ["-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"],
    'P-384' => [TestAuthority::publicPem(TestAuthority::key('secp384r1'))],
    'RSA' => [TestAuthority::publicPem(openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]) ?: throw new \RuntimeException('No RSA key.'))],
]);

it('refuses a previous counter outside the 32-bit range', function (int $previous): void {
    expect(fn () => testVerifier()->verifyAssertion("\xA0", 'x', attestedKey()['publicKey'], $previous))->toThrow(\InvalidArgumentException::class);
})->with([-1, 0x100000000, PHP_INT_MIN]);

it('leaves OpenSSL\'s error queue empty', function (array $options): void {
    assertionFailure(options: $options);

    expect(openssl_error_string())->toBeFalse();
})->with([
    'valid' => [[]],
    'junk signature' => [['signature' => 'junk']],
]);
