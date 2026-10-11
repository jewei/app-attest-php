<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\CategoryPolicy;
use AppAttest\Environment;
use AppAttest\Exception\Failure;
use AppAttest\Exception\VerificationException;
use AppAttest\Tests\Support\AttestationObject;
use AppAttest\Tests\Support\Bytes;
use AppAttest\Tests\Support\CborEncoder;
use AppAttest\Tests\Support\Map;
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

it('refuses a key ID that is not 32 bytes', function (\Closure $change): void {
    $attestation = testAttestation();
    $keyId = $change($attestation['keyId']);

    expect(failureOf(fn () => testVerifier()->verifyAttestation($attestation['attestation'], is_string($keyId) ? $keyId : '', testClientDataHash())))
        ->toBe(Failure::MalformedInput);
})->with([
    'empty' => [static fn (string $keyId): string => ''],
    '31 bytes' => [static fn (string $keyId): string => substr($keyId, 0, 31)],
    '33 bytes' => [static fn (string $keyId): string => $keyId."\0"],
    'Base64' => [static fn (string $keyId): string => base64_encode($keyId)],
]);

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
    '300 bytes, so the length has a high byte' => [str_repeat("\x07", 300)],
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
        ->and(attestationFailure(at: new \DateTimeImmutable('-1 day')))->toBe(Failure::InvalidCertificate);
});

it('refuses an expired intermediate or trust anchor while the credential certificate is valid', function (int $rootDays, int $intermediateDays): void {
    $authority = TestAuthority::create(rootDays: $rootDays, intermediateDays: $intermediateDays);
    $attestation = $authority->attest(testAppId(), testClientDataHash());
    $verify = fn (string $at) => failureOf(fn () => testVerifier(authority: $authority)->verifyAttestation(
        $attestation['attestation'], $attestation['keyId'], testClientDataHash(), new \DateTimeImmutable($at),
    ));

    expect($verify('+12 hours'))->toBeNull()
        ->and($verify('+2 days'))->toBe(Failure::InvalidCertificate);
})->with([
    'trust anchor' => [1, 3650],
    'intermediate' => [3650, 1],
]);

it('refuses a critical extension in the intermediate that the verifier does not check', function (): void {
    $authority = TestAuthority::create("basicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign\n1.2.3.4 = critical,DER:05:00");
    $attestation = $authority->attest(testAppId(), testClientDataHash());

    expect(failureOf(fn () => testVerifier(authority: $authority)->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash())))
        ->toBe(Failure::InvalidCertificate);
});

it('refuses an intermediate with the right key but another subject name', function (): void {
    $other = TestAuthority::shared()->intermediateWithSubject('Another App Attestation CA');
    $mutate = static function (AttestationObject $object) use ($other): void {
        $object->x5c = [$object->x5c[0], new Bytes($other)];
    };

    expect(attestationFailure(['mutate' => $mutate]))->toBe(Failure::InvalidCertificate)
        ->and(attestationFailure(['mutate' => static function (AttestationObject $object): void {
            $object->x5c = [$object->x5c[0], new Bytes(TestAuthority::shared()->intermediateWithSubject('Test App Attestation CA 1'))];
        }]))->toBeNull();
});

it('refuses the trust anchor as the intermediate', function (): void {
    $mutate = static function (AttestationObject $object): void {
        $object->x5c = [$object->x5c[0], new Bytes(TestAuthority::shared()->rootDer)];
    };

    expect(attestationFailure(['issuer' => 'root', 'mutate' => $mutate]))->toBe(Failure::InvalidCertificate);
});

it('refuses a trust anchor path length that leaves no room for the intermediate', function (): void {
    $authority = TestAuthority::create(rootExtensions: "basicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign");

    expect(fn () => testVerifier(authority: $authority))->toThrow(\InvalidArgumentException::class)
        ->and(fn () => testVerifier(authority: TestAuthority::create(rootExtensions: "basicConstraints = critical,CA:TRUE,pathlen:1\nkeyUsage = critical,keyCertSign")))
        ->not->toThrow(\InvalidArgumentException::class);
});

it('pads key coordinates with leading zero bytes', function (string $fixture): void {
    $key = TestAuthority::fixtureKey($fixture);
    $attestation = testAttestation(['key' => $key]);

    expect(failureOf(fn () => testVerifier()->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash())))->toBeNull();
})->with(['p256-leading-zero-x', 'p256-leading-zero-y']);

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
    'x5c as a map with text keys' => [static function (AttestationObject $object): void {
        $object->statement = ['x5c' => ['a' => $object->x5c[0], 'b' => $object->x5c[1]], 'receipt' => $object->receipt];
    }],
    'x5c as a map with the keys 0 and 1' => [static function (AttestationObject $object): void {
        $object->statement = ['x5c' => new Map([0 => $object->x5c[0], 1 => $object->x5c[1]]), 'receipt' => $object->receipt];
    }],
    'object as a list' => [static fn (AttestationObject $object) => $object->replaceWith(['apple-appattest', ['x5c' => $object->x5c, 'receipt' => $object->receipt], $object->authData])],
    'intermediate as text' => [static function (AttestationObject $object): void {
        $object->x5c = [$object->x5c[0], 'intermediate'];
    }],
    'credential public key not a map' => [static function (AttestationObject $object): void {
        $data = $object->authDataBytes();
        $keyStart = 37 + 18 + 32;
        $object->authData = new Bytes(substr($data, 0, $keyStart).CborEncoder::encode([1, 2]));
    }],
    'certificate as text' => [static function (AttestationObject $object): void {
        $object->x5c[0] = 'certificate';
    }],
    'short authData' => [static function (AttestationObject $object): void {
        $object->authData = new Bytes(substr($object->authDataBytes(), 0, 36));
    }],
    'authData cut one byte before the credential ID length ends' => [static function (AttestationObject $object): void {
        $object->authData = new Bytes(substr($object->authDataBytes(), 0, 37 + 17));
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

it('applies the validation category policy', function (mixed $category, \Closure $policy, ?Failure $failure): void {
    $extensions = $category === 'absent' ? null : ['apple_validation_category_01' => $category];
    $categories = $policy();

    expect(attestationFailure(['extensions' => $extensions], testVerifier(categories: $categories instanceof CategoryPolicy ? $categories : null)))->toBe($failure);
})->with([
    'TestFlight, any' => [new Bytes("\x02\0\0\0"), fn () => CategoryPolicy::any(), null],
    'TestFlight, allowed' => [new Bytes("\x02\0\0\0"), fn () => CategoryPolicy::only(ValidationCategory::TestFlight), null],
    'TestFlight, App Store only' => [new Bytes("\x02\0\0\0"), fn () => CategoryPolicy::only(ValidationCategory::AppStore), Failure::CategoryNotAllowed],
    'App Store, App Store or missing' => [new Bytes("\x04\0\0\0"), fn () => CategoryPolicy::onlyOrMissing(ValidationCategory::AppStore), null],
    'TestFlight, App Store or missing' => [new Bytes("\x02\0\0\0"), fn () => CategoryPolicy::onlyOrMissing(ValidationCategory::AppStore), Failure::CategoryNotAllowed],
    'second of two allowed or missing' => [new Bytes("\x02\0\0\0"), fn () => CategoryPolicy::onlyOrMissing(ValidationCategory::AppStore, ValidationCategory::TestFlight), null],
    'second of two allowed' => [new Bytes("\x04\0\0\0"), fn () => CategoryPolicy::only(ValidationCategory::TestFlight, ValidationCategory::AppStore), null],
    'invalid 0' => [new Bytes("\0\0\0\0"), fn () => CategoryPolicy::any(), Failure::CategoryNotAllowed],
    'restricted 7' => [new Bytes("\x07\0\0\0"), fn () => CategoryPolicy::any(), Failure::CategoryNotAllowed],
    'restricted 9' => [new Bytes("\x09\0\0\0"), fn () => CategoryPolicy::any(), Failure::CategoryNotAllowed],
    'unknown 11' => [new Bytes("\x0B\0\0\0"), fn () => CategoryPolicy::any(), Failure::CategoryNotAllowed],
    'unknown 11, missing allowed' => [new Bytes("\x0B\0\0\0"), fn () => CategoryPolicy::onlyOrMissing(ValidationCategory::AppStore), Failure::CategoryNotAllowed],
    'big-endian 2' => [new Bytes("\0\0\0\x02"), fn () => CategoryPolicy::any(), Failure::CategoryNotAllowed],
    'integer 4' => [4, fn () => CategoryPolicy::only(ValidationCategory::AppStore), null],
    'integer 0' => [0, fn () => CategoryPolicy::any(), Failure::CategoryNotAllowed],
    'integer 2^32 - 1' => [0xFFFFFFFF, fn () => CategoryPolicy::any(), Failure::CategoryNotAllowed],
    'absent, any' => ['absent', fn () => CategoryPolicy::any(), null],
    'absent, only' => ['absent', fn () => CategoryPolicy::only(ValidationCategory::TestFlight), Failure::CategoryNotAllowed],
    'absent, only or missing' => ['absent', fn () => CategoryPolicy::onlyOrMissing(ValidationCategory::TestFlight), null],
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

it('accepts an empty extensions map and refuses an empty array', function (): void {
    expect(attestationFailure(['extensions' => new Map([])]))->toBeNull()
        ->and(attestationFailure(['extensions' => []]))->toBe(Failure::MalformedInput);
});

it('accepts a valid attestation at the size limit and refuses one byte more', function (int $extra, ?Failure $failure): void {
    $mutate = static function (AttestationObject $object) use ($extra): void {
        $object->receipt = new Bytes('');
        $base = strlen($object->encode());
        // An empty byte string has a 1-byte head; one of 256 to 65535 bytes has a 3-byte head.
        $object->receipt = new Bytes(str_repeat('r', Verifier::MAX_ATTESTATION_BYTES - $base - 2 + $extra));
    };
    $attestation = testAttestation(['mutate' => $mutate]);

    expect(strlen($attestation['attestation']))->toBe(Verifier::MAX_ATTESTATION_BYTES + $extra)
        ->and(failureOf(fn () => testVerifier()->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash())))->toBe($failure);
})->with([
    'at the limit' => [0, null],
    'one byte over' => [1, Failure::MalformedInput],
]);

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
    'another authority\'s intermediate' => [['mutate' => static function (AttestationObject $object): void {
        $object->x5c = [$object->x5c[0], new Bytes(TestAuthority::create()->intermediateDer)];
    }]],
    'a changed credential signature' => [['mutate' => static function (AttestationObject $object): void {
        $certificate = $object->certificate(0);
        $object->x5c = [new Bytes(substr($certificate, 0, -1).chr(ord($certificate[-1]) ^ 1)), $object->x5c[1]];
    }]],
    'junk certificate' => [['mutate' => static function (AttestationObject $object): void {
        $object->x5c[0] = new Bytes("\x30\x03\x02\x01\x01");
    }]],
]);

it('names the expected keys when the structure is wrong', function (): void {
    $attestation = testAttestation(['mutate' => static function (AttestationObject $object): void {
        $object->extraFields = ['extra' => 1];
    }]);

    expect(fn () => testVerifier()->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash()))
        ->toThrow(VerificationException::class, 'The attestation object is not a map with exactly the keys fmt, attStmt, authData.');
});

it('refuses a key from a platform other than iPhone and iPad', function (string $platform, ?Failure $failure): void {
    expect(attestationFailure(['credentialExtensions' => "basicConstraints = critical,CA:FALSE\n".TestAuthority::platformExtension($platform)]))->toBe($failure);
})->with([
    'iPhone and iPad' => ['iphoneos', null],
    'macOS' => ['macosx', Failure::UnsupportedPlatform],
    'another platform' => ['xros', Failure::UnsupportedPlatform],
]);

it('refuses the anchor\'s key under another certificate as the intermediate', function (): void {
    $copy = TestAuthority::shared()->rootCopy();

    expect($copy)->not->toBe(TestAuthority::shared()->rootDer)
        ->and(attestationFailure(['issuer' => 'root', 'mutate' => static function (AttestationObject $object) use ($copy): void {
            $object->x5c = [$object->x5c[0], new Bytes($copy)];
        }]))->toBe(Failure::InvalidCertificate);
});

it('refuses a self-issued intermediate with its own key', function (): void {
    $selfIssued = TestAuthority::shared()->intermediateWithSubject('Test App Attestation Root CA');

    expect(attestationFailure(['mutate' => static function (AttestationObject $object) use ($selfIssued): void {
        $object->x5c = [$object->x5c[0], new Bytes($selfIssued)];
    }]))->toBe(Failure::InvalidCertificate);
});

it('refuses an intermediate issued under another name, even with the anchor\'s key', function (): void {
    $other = TestAuthority::shared()->intermediateIssuedUnder('Another App Attestation Root CA');
    $same = TestAuthority::shared()->intermediateIssuedUnder('Test App Attestation Root CA');
    $with = static fn (string $intermediate): \Closure => static function (AttestationObject $object) use ($intermediate): void {
        $object->x5c = [$object->x5c[0], new Bytes($intermediate)];
    };

    expect(attestationFailure(['mutate' => $with($other)]))->toBe(Failure::InvalidCertificate)
        ->and(attestationFailure(['mutate' => $with($same)]))->toBeNull();
});

it('accepts a P-256 intermediate and refuses another curve', function (string $curve, ?Failure $failure): void {
    $authority = TestAuthority::create(intermediateCurve: $curve);
    $attestation = $authority->attest(testAppId(), testClientDataHash());

    expect(failureOf(fn () => testVerifier(authority: $authority)->verifyAttestation($attestation['attestation'], $attestation['keyId'], testClientDataHash())))
        ->toBe($failure);
})->with([
    'P-256' => ['prime256v1', null],
    'P-521' => ['secp521r1', Failure::InvalidCertificate],
]);

it('reads the platform field among other fields', function (string $extraFields, ?Failure $failure): void {
    $lines = "basicConstraints = critical,CA:FALSE\n".TestAuthority::platformExtension('iphoneos', $extraFields);

    expect(attestationFailure(['credentialExtensions' => $lines]))->toBe($failure);
})->with([
    'a low-tag constructed field' => ["\xA4\x03\x02\x01\x00", null],
    'a primitive field' => ["\x85\x01\x00", null],
    'another high-tag field' => ["\xBF\x8A\x78\x06\x04\x04\x32\x37\x2E\x30", null],
    'a universal field' => ["\x04\x01\x00", Failure::InvalidCertificate],
]);

it('refuses a key with Apple\'s macOS access-control blob, even without a platform field', function (): void {
    $macAcl = (string) base64_decode('MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB', true);

    expect(attestationFailure(['credentialExtensions' => "basicConstraints = critical,CA:FALSE\n".TestAuthority::aclExtension($macAcl)]))
        ->toBe(Failure::UnsupportedPlatform)
        ->and(attestationFailure(['credentialExtensions' => "basicConstraints = critical,CA:FALSE\n".TestAuthority::aclExtension('an iOS policy')]))
        ->toBeNull();
});

it('refuses an intermediate with the anchor\'s key under another name', function (): void {
    $intermediate = TestAuthority::shared()->customIntermediate('Another App Attestation CA', anchorKey: true);
    $control = TestAuthority::shared()->customIntermediate('Another App Attestation CA', anchorKey: false);

    expect(attestationFailure(['intermediate' => $intermediate]))->toBe(Failure::InvalidCertificate)
        ->and(attestationFailure(['intermediate' => $control]))->toBeNull();
});

it('refuses a self-issued intermediate that the credential certificate names', function (): void {
    $intermediate = TestAuthority::shared()->customIntermediate('Test App Attestation Root CA', anchorKey: false);

    expect(attestationFailure(['intermediate' => $intermediate]))->toBe(Failure::InvalidCertificate);
});
