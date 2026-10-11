<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Internal\ByteString;
use AppAttest\Internal\Cbor;
use AppAttest\Internal\CborMap;
use AppAttest\Internal\Der;
use AppAttest\Testing\TestAuthority;

it('writes App Attest data as a device does', function (): void {
    $appId = new AppId('ABCDE12345', 'com.example.app');
    $device = TestAuthority::create()->device($appId, bundleVersion: '2.4');
    $attestation = Cbor::decode($device->attest(hash('sha256', 'c', true)));
    $assertion = Cbor::decode($device->assert('GET /me'));
    $authData = $attestation instanceof CborMap && $attestation->get('authData') instanceof ByteString ? $attestation->get('authData')->value : '';
    $authenticatorData = $assertion instanceof CborMap && $assertion->get('authenticatorData') instanceof ByteString ? $assertion->get('authenticatorData')->value : '';
    $extensions = Cbor::decode(substr($authenticatorData, 37));

    [$coseKey] = Cbor::decodePrefix($authData, 37 + 16 + 2 + 32);
    $statement = $attestation instanceof CborMap ? $attestation->get('attStmt') : null;
    $receipt = $statement instanceof CborMap ? $statement->get('receipt') : null;

    expect($coseKey instanceof CborMap ? [$coseKey->get(1), $coseKey->get(3), $coseKey->get(-1)] : null)->toBe([2, -7, 1])
        ->and($coseKey instanceof CborMap && $coseKey->get(-2) instanceof ByteString && $coseKey->get(-3) instanceof ByteString
            ? hash('sha256', "\x04".$coseKey->get(-2)->value.$coseKey->get(-3)->value, true) : null)->toBe($device->keyId)
        ->and($receipt instanceof ByteString ? $receipt->value : null)->toBe('test receipt')
        ->and(ord($authData[32]))->toBe(0xC0)
        ->and(ord($authenticatorData[32]))->toBe(0xC0)
        ->and(substr($authenticatorData, 0, 32))->toBe($appId->hash())
        ->and(substr($authenticatorData, 33, 4))->toBe("\0\0\0\x01")
        ->and($extensions instanceof CborMap ? $extensions->get('apple_bundle_version_01') : null)->toBe('2.4')
        ->and($extensions instanceof CborMap && $extensions->get('apple_validation_category_01') instanceof ByteString
            ? $extensions->get('apple_validation_category_01')->value : null)->toBe("\x02\0\0\0");
});

it('writes no extensions and the AT flag only without a category', function (): void {
    $device = TestAuthority::create()->device(new AppId('ABCDE12345', 'com.example.app'), category: null);
    $attestation = Cbor::decode($device->attest(hash('sha256', 'c', true)));
    $authData = $attestation instanceof CborMap && $attestation->get('authData') instanceof ByteString ? $attestation->get('authData')->value : '';
    $assertion = Cbor::decode($device->assert('GET /me'));
    $authenticatorData = $assertion instanceof CborMap && $assertion->get('authenticatorData') instanceof ByteString ? $assertion->get('authenticatorData')->value : '';

    expect(strlen($authenticatorData))->toBe(37)
        ->and(ord($authenticatorData[32]))->toBe(0x40)
        ->and(ord($authData[32]))->toBe(0x40);
});

it('issues credential certificates for 3 days and CA certificates for 10 years, and leaves no temporary files', function (): void {
    // Only this process's files: parallel workers create and delete their own.
    $pattern = sys_get_temp_dir().'/app-attest-test-'.getmypid().'-*';
    $before = glob($pattern) ?: [];
    $device = TestAuthority::create()->device(new AppId('ABCDE12345', 'com.example.app'));
    $attestation = Cbor::decode($device->attest(hash('sha256', 'c', true)));
    $statement = $attestation instanceof CborMap ? $attestation->get('attStmt') : null;
    $x5c = $statement instanceof CborMap ? $statement->get('x5c') : null;
    $credential = is_array($x5c) && $x5c[0] instanceof ByteString ? Der::certificate($x5c[0]->value) : null;
    $intermediate = is_array($x5c) && $x5c[1] instanceof ByteString ? Der::certificate($x5c[1]->value) : null;

    expect($credential === null ? null : $credential['notAfter'] - $credential['notBefore'])->toBe(3 * 86400)
        ->and($intermediate === null ? null : $intermediate['notAfter'] - $intermediate['notBefore'])->toBe(3650 * 86400)
        ->and(glob($pattern) ?: [])->toBe($before);
});
