<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\Tests\Support\AttestationObject;
use AppAttest\Tests\Support\Bytes;
use AppAttest\Tests\Support\CborEncoder;
use AppAttest\Tests\Support\TestAuthority;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

it('accepts a valid attestation and returns the key', function (): void {
    $attestation = testAttestation();
    $key = testVerifier()->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash());

    expect($key->keyId)->toBe($attestation['keyId'])
        ->and($key->publicKey)->toBe($attestation['publicKey'])
        ->and($key->receipt)->toBe('test receipt')
        ->and($key->environment)->toBe(Environment::Production)
        ->and($key->validationCategory)->toBe(ValidationCategory::TestFlight)
        ->and($key->bundleVersion)->toBe('1.0');
});

it('accepts a development key in the development environment only', function (): void {
    $options = ['aaguid' => 'appattestdevelop'];

    expect(attestationFailure($options, testVerifier(Environment::Development)))->toBeNull()
        ->and(attestationFailure($options))->toBe(Failure::EnvironmentMismatch)
        ->and(attestationFailure([], testVerifier(Environment::Development)))->toBe(Failure::EnvironmentMismatch);
});

it('refuses other AAGUIDs', function (string $aaguid): void {
    expect(attestationFailure(['aaguid' => $aaguid]))->toBe(Failure::EnvironmentMismatch);
})->with([
    'all zero' => [str_repeat("\0", 16)],
    'production with a trailing byte' => ["appattest\0\0\0\0\0\0\x01"],
    'development in capitals' => ['APPATTESTDEVELOP'],
]);

it('refuses a client data hash that differs from the attested one', function (): void {
    $attestation = testAttestation();

    expect(failureOf(fn () => testVerifier()->verifyAttestation($attestation['attestation'], $attestation['keyId'], hash('sha256', 'other challenge', true))))
        ->toBe(Failure::NonceMismatch);
});

it('refuses a certificate nonce that is not SHA-256(authData || clientDataHash)', function (): void {
    expect(attestationFailure(['nonce' => random_bytes(32)]))->toBe(Failure::NonceMismatch)
        ->and(attestationFailure(['nonce' => random_bytes(31)]))->toBe(Failure::NonceMismatch);
});

it('refuses a credential certificate without a usable nonce extension', function (array $options): void {
    expect(attestationFailure($options))->toBe(Failure::InvalidCertificate);
})->with([
    'missing' => [['nonce' => null]],
    'bare octet string' => [['nonceExtension' => "\x04\x20".str_repeat("\x01", 32)]],
    'wrong context tag' => [['nonceExtension' => "\x30\x24\xA0\x22\x04\x20".str_repeat("\x01", 32)]],
    'two elements' => [['nonceExtension' => "\x30\x26\xA1\x22\x04\x20".str_repeat("\x01", 32)."\x05\x00"]],
]);

it('refuses a key ID that is not the credential key\'s hash', function (): void {
    $attestation = testAttestation();

    expect(failureOf(fn () => testVerifier()->verifyAttestation($attestation['attestation'], random_bytes(32), testClientDataHash())))
        ->toBe(Failure::KeyIdMismatch);
});

it('refuses a key ID that is not 32 bytes', function (int $length): void {
    $attestation = testAttestation();

    expect(failureOf(fn () => testVerifier()->verifyAttestation($attestation['attestation'], substr($attestation['keyId'].'xx', 0, $length), testClientDataHash())))
        ->toBe(Failure::MalformedInput);
})->with([0, 31, 33, 44]);

it('refuses another App ID', function (): void {
    expect(attestationFailure([], testVerifier(appId: new AppId('ABCDE12345', 'com.example.other'))))->toBe(Failure::AppIdMismatch)
        ->and(attestationFailure([], testVerifier(appId: new AppId('ZZZZZ12345', 'com.example.app'))))->toBe(Failure::AppIdMismatch)
        ->and(attestationFailure(['rpIdHash' => hash('sha256', 'com.example.app', true)]))->toBe(Failure::AppIdMismatch);
});

it('refuses a counter above 0', function (int $counter): void {
    expect(attestationFailure(['counter' => $counter]))->toBe(Failure::NonZeroCounter);
})->with([1, 0xFFFFFFFF]);

it('refuses a credential ID that is not the key ID', function (string $credentialId): void {
    expect(attestationFailure(['credentialId' => $credentialId]))->toBe(Failure::CredentialIdMismatch);
})->with([
    'other 32 bytes' => [str_repeat("\x07", 32)],
    'empty' => [''],
    'prefix' => [str_repeat("\x07", 16)],
]);

it('refuses a certificate chain that does not lead to the trust anchor', function (): void {
    $other = TestAuthority::create();
    $attestation = $other->attest(testAppId(), testClientDataHash());

    expect(failureOf(fn () => testVerifier()->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash())))
        ->toBe(Failure::InvalidCertificate);
});

it('refuses a credential certificate that the intermediate did not issue', function (): void {
    expect(attestationFailure(['issuer' => 'root']))->toBe(Failure::InvalidCertificate);
});

it('refuses an intermediate certificate from another authority', function (): void {
    $intermediate = TestAuthority::create()->intermediateDer;
    $mutate = static function (AttestationObject $object) use ($intermediate): void {
        $object->x5c = [$object->x5c[0], new Bytes($intermediate)];
    };

    expect(attestationFailure(['mutate' => $mutate]))->toBe(Failure::InvalidCertificate);
});

it('refuses an intermediate that is not a CA or may not sign certificates', function (string $extensions): void {
    $authority = TestAuthority::create($extensions);
    $attestation = $authority->attest(testAppId(), testClientDataHash());

    expect(failureOf(fn () => testVerifier(authority: $authority)->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash())))
        ->toBe(Failure::InvalidCertificate);
})->with([
    'not a CA' => ["basicConstraints = critical,CA:FALSE\nkeyUsage = critical,keyCertSign"],
    'no basic constraints' => ['keyUsage = critical,keyCertSign'],
    'no certificate signing' => ["basicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature"],
    'no key usage' => ['basicConstraints = critical,CA:TRUE'],
]);

it('accepts the test intermediate under its own anchor', function (): void {
    $authority = TestAuthority::create();
    $attestation = $authority->attest(testAppId(), testClientDataHash());

    expect(failureOf(fn () => testVerifier(authority: $authority)->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash())))
        ->toBeNull();
});

it('refuses a credential certificate that is a CA', function (): void {
    expect(attestationFailure(['credentialExtensions' => "basicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature"]))
        ->toBe(Failure::InvalidCertificate);
});

it('refuses a critical extension that the verifier does not check', function (): void {
    expect(attestationFailure(['credentialExtensions' => "basicConstraints = critical,CA:FALSE\n1.2.3.4 = critical,DER:05:00"]))
        ->toBe(Failure::InvalidCertificate);
});

it('accepts a non-critical extension that the verifier does not check', function (): void {
    expect(attestationFailure(['credentialExtensions' => "basicConstraints = critical,CA:FALSE\n1.2.3.4 = DER:05:00"]))->toBeNull();
});

it('checks certificate validity at the given time', function (): void {
    expect(attestationFailure(at: new \DateTimeImmutable('+1 day')))->toBeNull()
        ->and(attestationFailure(at: new \DateTimeImmutable('+4 days')))->toBe(Failure::InvalidCertificate)
        ->and(attestationFailure(at: new \DateTimeImmutable('-1 day')))->toBe(Failure::InvalidCertificate)
        ->and(attestationFailure(at: new \DateTimeImmutable('+11 years')))->toBe(Failure::InvalidCertificate);
});

it('refuses a credential key that is not P-256', function (): void {
    expect(attestationFailure(['curve' => 'secp384r1']))->toBe(Failure::InvalidCertificate);
});

it('refuses a format other than apple-appattest', function (mixed $format): void {
    $mutate = static function (AttestationObject $object) use ($format): void {
        $object->format = $format;
    };

    expect(attestationFailure(['mutate' => $mutate]))->toBe(Failure::UnsupportedFormat);
})->with([
    'packed' => ['packed'],
    'byte string' => [new Bytes('apple-appattest')],
    'integer' => [1],
]);

it('refuses an object that is not Apple\'s structure', function (\Closure $mutate): void {
    expect(attestationFailure(['mutate' => $mutate]))->toBe(Failure::MalformedInput);
})->with([
    'not a map' => [static fn (AttestationObject $object) => $object->replaceWith('apple-appattest')],
    'list' => [static fn (AttestationObject $object) => $object->replaceWith([$object->format, $object->authData])],
    'extra field' => [static function (AttestationObject $object): void {
        $object->extraFields = ['extra' => 1];
    }],
    'missing authData' => [static function (AttestationObject $object): void {
        $object->omit = ['authData'];
    }],
    'authData as text' => [static function (AttestationObject $object): void {
        $object->authData = 'text';
    }],
    'attStmt not a map' => [static function (AttestationObject $object): void {
        $object->statement = 'x';
    }],
    'attStmt extra field' => [static function (AttestationObject $object): void {
        $object->extraStatementFields = ['alg' => -7];
    }],
    'no receipt' => [static function (AttestationObject $object): void {
        $object->omit = ['receipt'];
    }],
    'no x5c' => [static function (AttestationObject $object): void {
        $object->omit = ['x5c'];
    }],
    'receipt as text' => [static function (AttestationObject $object): void {
        $object->receipt = 'r';
    }],
    'one certificate' => [static function (AttestationObject $object): void {
        $object->x5c = [$object->x5c[0]];
    }],
    'three certificates' => [static function (AttestationObject $object): void {
        $object->x5c[] = $object->x5c[1];
    }],
    'x5c as a map' => [static function (AttestationObject $object): void {
        $object->statement = ['x5c' => ['a' => $object->x5c[0], 'b' => $object->x5c[1]], 'receipt' => $object->receipt];
    }],
    'certificate as text' => [static function (AttestationObject $object): void {
        $object->x5c[0] = 'certificate';
    }],
    'short authData' => [static function (AttestationObject $object): void {
        $object->authData = new Bytes(substr($object->authDataBytes(), 0, 36));
    }],
    'authData cut in the AAGUID' => [static function (AttestationObject $object): void {
        $object->authData = new Bytes(substr($object->authDataBytes(), 0, 45));
    }],
    'authData cut in the credential ID' => [static function (AttestationObject $object): void {
        $object->authData = new Bytes(substr($object->authDataBytes(), 0, 70));
    }],
    'authData cut in the public key' => [static function (AttestationObject $object): void {
        $object->authData = new Bytes(substr($object->authDataBytes(), 0, 100));
    }],
]);

it('refuses certificates that are not DER', function (\Closure $change): void {
    $mutate = static function (AttestationObject $object) use ($change): void {
        $certificate = $change($object->certificate(0));
        $object->x5c[0] = new Bytes(is_string($certificate) ? $certificate : '');
    };

    expect(attestationFailure(['mutate' => $mutate]))->toBe(Failure::InvalidCertificate);
})->with([
    'junk' => [static fn (string $der): string => 'junk'],
    'trailing byte' => [static fn (string $der): string => $der."\0"],
    'truncated' => [static fn (string $der): string => substr($der, 0, -1)],
    'signature changed' => [static fn (string $der): string => substr($der, 0, -1).chr(ord($der[-1]) ^ 1)],
]);

it('refuses the certificates in the wrong order', function (): void {
    $mutate = static function (AttestationObject $object): void {
        $object->x5c = array_reverse($object->x5c);
    };

    expect(attestationFailure(['mutate' => $mutate]))->toBe(Failure::InvalidCertificate);
});

it('applies the validation category policy', function (mixed $category, ?array $allowed, ?Failure $failure): void {
    $extensions = $category === 'absent' ? null : ['apple_validation_category_01' => $category];

    expect(attestationFailure(['extensions' => $extensions], testVerifier(categories: $allowed)))->toBe($failure);
})->with([
    'TestFlight, any' => [new Bytes("\x02\0\0\0"), null, null],
    'TestFlight, allowed' => [new Bytes("\x02\0\0\0"), [ValidationCategory::TestFlight], null],
    'TestFlight, App Store only' => [new Bytes("\x02\0\0\0"), [ValidationCategory::AppStore], Failure::CategoryNotAllowed],
    'invalid 0' => [new Bytes("\0\0\0\0"), null, Failure::CategoryNotAllowed],
    'restricted 7' => [new Bytes("\x07\0\0\0"), null, Failure::CategoryNotAllowed],
    'restricted 9' => [new Bytes("\x09\0\0\0"), null, Failure::CategoryNotAllowed],
    'unknown 11' => [new Bytes("\x0B\0\0\0"), null, Failure::CategoryNotAllowed],
    'big-endian 2' => [new Bytes("\0\0\0\x02"), null, Failure::CategoryNotAllowed],
    'integer 4' => [4, [ValidationCategory::AppStore], null],
    'absent, any' => ['absent', null, null],
    'absent, list' => ['absent', [ValidationCategory::TestFlight], Failure::CategoryNotAllowed],
]);

it('returns the category and bundle version from the extensions', function (): void {
    $attestation = testAttestation(['extensions' => ['apple_validation_category_01' => new Bytes("\x0A\0\0\0"), 'apple_bundle_version_01' => '27.1 (5)', 'other' => [1, 2]]]);
    $key = testVerifier()->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash());

    expect($key->validationCategory)->toBe(ValidationCategory::Other)
        ->and($key->bundleVersion)->toBe('27.1 (5)');
});

it('returns no category or bundle version without extensions', function (): void {
    $attestation = testAttestation(['extensions' => null]);
    $key = testVerifier()->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash());

    expect($key->validationCategory)->toBeNull()
        ->and($key->bundleVersion)->toBeNull();
});

it('refuses malformed extensions', function (array|string $extensions): void {
    expect(attestationFailure(['extensions' => $extensions]))->toBe(Failure::MalformedInput);
})->with([
    'a list' => [[1, 2]],
    'a text string' => [CborEncoder::encode('extensions')],
    'bundle version as bytes' => [['apple_bundle_version_01' => new Bytes('1.0')]],
    'category of three bytes' => [['apple_validation_category_01' => new Bytes("\x02\0\0")]],
    'category of five bytes' => [['apple_validation_category_01' => new Bytes("\x02\0\0\0\0")]],
    'negative category' => [['apple_validation_category_01' => -1]],
    'category above 32 bits' => [['apple_validation_category_01' => 0x100000000]],
    'trailing byte' => [CborEncoder::encode(['apple_bundle_version_01' => '1'])."\0"],
    'truncated' => [substr(CborEncoder::encode(['apple_bundle_version_01' => '1.0']), 0, -1)],
]);

it('accepts an empty extensions map', function (): void {
    expect(attestationFailure(['extensions' => []]))->toBeNull();
});

it('refuses an empty or oversized attestation', function (string $attestation): void {
    expect(failureOf(fn () => testVerifier()->verifyAttestation($attestation, str_repeat("\0", 32), testClientDataHash())))
        ->toBe(Failure::MalformedInput);
})->with([
    'empty' => [''],
    'one byte over the limit' => [str_repeat("\xA0", Verifier::MAX_ATTESTATION_BYTES + 1)],
]);

it('requires a client data hash', function (): void {
    $attestation = testAttestation();

    expect(fn () => testVerifier()->verifyAttestation($attestation['attestation'], $attestation['keyId'], ''))
        ->toThrow(\InvalidArgumentException::class);
});

it('leaves OpenSSL\'s error queue empty', function (array $options): void {
    attestationFailure($options);

    expect(openssl_error_string())->toBeFalse();
})->with([
    'valid' => [[]],
    'wrong issuer' => [['issuer' => 'root']],
    'junk certificate' => [['mutate' => static function (AttestationObject $object): void {
        $object->x5c[0] = new Bytes("\x30\x03\x02\x01\x01");
    }]],
]);
