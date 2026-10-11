<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\Tests\Support\AssertionObject;
use AppAttest\Tests\Support\Bytes;
use AppAttest\Tests\Support\CborEncoder;
use AppAttest\Tests\Support\TestAuthority;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

it('accepts a valid assertion and returns the new counter', function (): void {
    $key = attestedKey();
    $assertion = TestAuthority::assertion($key['key'], testAppId(), 'POST /orders', 5);
    $verified = testVerifier()->verifyAssertion($assertion, 'POST /orders', $key['publicKey'], 4, Environment::Production);

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

    $assertion = CborEncoder::encode(['signature' => new Bytes($signature), 'authenticatorData' => new Bytes($authenticatorData)]);

    expect(failureOf(fn () => testVerifier()->verifyAssertion($assertion, 'POST /orders', $key['publicKey'], 0, Environment::Production)))->toBe(Failure::InvalidSignature);
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
    $verified = testVerifier()->verifyAssertion($assertion, 'GET /me', $key['publicKey'], 0, Environment::Production);

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

it('refuses a key from another environment', function (): void {
    $key = attestedKey();
    $assertion = TestAuthority::assertion($key['key'], testAppId(), 'GET /me', 1);

    expect(failureOf(fn () => testVerifier()->verifyAssertion($assertion, 'GET /me', $key['publicKey'], 0, Environment::Development)))
        ->toBe(Failure::EnvironmentMismatch)
        ->and(failureOf(fn () => testVerifier(Environment::Development)->verifyAssertion($assertion, 'GET /me', $key['publicKey'], 0, Environment::Development)))
        ->toBeNull();
});

it('accepts a signed assertion at the size limit and refuses one byte more', function (): void {
    $key = attestedKey();
    $sized = static function (int $size) use ($key): string {
        $padding = static fn (int $length): string => TestAuthority::assertion($key['key'], testAppId(), 'GET /me', 1, ['extensions' => ['apple_bundle_version_01' => str_repeat('1', $length)]]);
        $length = 300;

        // An ECDSA signature has 68 to 72 bytes, so correct the padding from each result until the size is exact.
        for ($attempt = 0; $attempt < 200; $attempt++) {
            $assertion = $padding($length);

            if (strlen($assertion) === $size) {
                return $assertion;
            }

            $length += $size - strlen($assertion);
        }

        throw new \RuntimeException('No assertion of the exact size.');
    };

    expect(failureOf(fn () => testVerifier()->verifyAssertion($sized(Verifier::MAX_ASSERTION_BYTES), 'GET /me', $key['publicKey'], 0, Environment::Production)))->toBeNull()
        ->and(failureOf(fn () => testVerifier()->verifyAssertion($sized(Verifier::MAX_ASSERTION_BYTES + 1), 'GET /me', $key['publicKey'], 0, Environment::Production)))->toBe(Failure::MalformedInput);
});

it('refuses an empty or oversized assertion', function (string $assertion): void {
    expect(failureOf(fn () => testVerifier()->verifyAssertion($assertion, 'x', attestedKey()['publicKey'], 0, Environment::Production)))->toBe(Failure::MalformedInput);
})->with([
    'empty' => [''],
    'one byte over the limit' => [str_repeat("\xA0", Verifier::MAX_ASSERTION_BYTES + 1)],
]);

it('refuses a stored public key that is not an EC P-256 PEM', function (string $publicKey): void {
    expect(fn () => testVerifier()->verifyAssertion("\xA0", 'x', $publicKey, 0, Environment::Production))->toThrow(\InvalidArgumentException::class);
})->with([
    'empty' => [''],
    'file path to a real P-256 key' => [(static function (): string {
        $path = tempnam(sys_get_temp_dir(), 'app-attest-key-');

        if ($path === false) {
            throw new \RuntimeException('tempnam failed.');
        }

        file_put_contents($path, TestAuthority::publicPem(TestAuthority::key()));
        register_shutdown_function(static fn (): bool => unlink($path));

        return 'file://'.$path;
    })()],
    'certificate' => [TestAuthority::shared()->rootPem],
    'bad PEM' => ["-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"],
    'P-384' => [TestAuthority::publicPem(TestAuthority::key('secp384r1'))],
    'RSA' => [TestAuthority::publicPem(openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]) ?: throw new \RuntimeException('No RSA key.'))],
]);

it('refuses a previous counter outside the 32-bit range', function (int $previous): void {
    expect(fn () => testVerifier()->verifyAssertion("\xA0", 'x', attestedKey()['publicKey'], $previous, Environment::Production))->toThrow(\InvalidArgumentException::class);
})->with([-1, 0x100000000, PHP_INT_MIN]);

it('leaves OpenSSL\'s error queue empty', function (\Closure $call): void {
    $call();

    expect(openssl_error_string())->toBeFalse();
})->with([
    'valid' => [fn () => assertionFailure()],
    'junk signature' => [fn () => assertionFailure(options: ['signature' => 'junk'])],
    'a stored key with a bad PEM body' => [function (): void {
        try {
            testVerifier()->verifyAssertion("\xA0", 'x', "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", 0, Environment::Production);
        } catch (\InvalidArgumentException) {
            // Expected: the stored key is not a PEM key.
        }
    }],
]);

it('reads assertion extensions only with the ED flag', function (string $flags, ?Failure $failure): void {
    expect(assertionFailure(options: ['flags' => $flags]))->toBe($failure);
})->with([
    'AT and ED' => ["\xC0", null],
    'ED only' => ["\x80", null],
    'AT only' => ["\x40", Failure::MalformedInput],
    'no flags' => ["\x00", Failure::MalformedInput],
]);

it('refuses extensions moved from the client data hash into the authenticator data', function (): void {
    // A modified app signs SHA256(authData || X || SHA256(clientData)) and sends authData || X: the signature
    // matches, but without the ED flag the extra bytes are refused.
    $key = attestedKey();
    $forged = CborEncoder::encode(['apple_validation_category_01' => new Bytes("\x04\0\0\0")]);
    $authenticatorData = testAppId()->hash()."\x40".pack('N', 1);
    $nonce = hash('sha256', $authenticatorData.$forged.hash('sha256', 'GET /me', true), true);
    openssl_sign($nonce, $signature, $key['key'], OPENSSL_ALGO_SHA256);
    $assertion = CborEncoder::encode(['signature' => new Bytes(is_string($signature) ? $signature : ''), 'authenticatorData' => new Bytes($authenticatorData.$forged)]);

    expect(failureOf(fn () => testVerifier(categories: [ValidationCategory::AppStore])->verifyAssertion($assertion, 'GET /me', $key['publicKey'], 0, Environment::Production)))
        ->toBe(Failure::MalformedInput);
});

it('refuses a stored key string that is not exactly one PUBLIC KEY block', function (\Closure $pem): void {
    $publicKey = attestedKey()['publicKey'];
    $value = $pem($publicKey);

    expect(fn () => testVerifier()->verifyAssertion("\xA0", 'x', is_string($value) ? $value : '', 0, Environment::Production))
        ->toThrow(\InvalidArgumentException::class);
})->with([
    'a key and then a certificate' => [fn (string $key): string => $key.TestAuthority::shared()->rootPem],
    'two keys' => [fn (string $key): string => $key.$key],
    'text after the key' => [fn (string $key): string => $key.'trailing'],
]);
