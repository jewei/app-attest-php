<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Internal\ByteString;
use AppAttest\Internal\Cbor;
use AppAttest\Internal\CborMap;
use AppAttest\Testing\TestAuthority;

it('writes App Attest data as a device does', function (): void {
    $appId = new AppId('ABCDE12345', 'com.example.app');
    $device = TestAuthority::create()->device($appId, bundleVersion: '2.4');
    $attestation = Cbor::decode($device->attest(hash('sha256', 'c', true)));
    $assertion = Cbor::decode($device->assert('GET /me'));
    $authData = $attestation instanceof CborMap && $attestation->get('authData') instanceof ByteString ? $attestation->get('authData')->value : '';
    $authenticatorData = $assertion instanceof CborMap && $assertion->get('authenticatorData') instanceof ByteString ? $assertion->get('authenticatorData')->value : '';
    $extensions = Cbor::decode(substr($authenticatorData, 37));

    expect(ord($authData[32]))->toBe(0x40)
        ->and(ord($authenticatorData[32]))->toBe(0xC0)
        ->and(substr($authenticatorData, 0, 32))->toBe($appId->hash())
        ->and(substr($authenticatorData, 33, 4))->toBe("\0\0\0\x01")
        ->and($extensions instanceof CborMap ? $extensions->get('apple_bundle_version_01') : null)->toBe('2.4')
        ->and($extensions instanceof CborMap && $extensions->get('apple_validation_category_01') instanceof ByteString
            ? $extensions->get('apple_validation_category_01')->value : null)->toBe("\x02\0\0\0");
});

it('writes no extensions and the AT flag only without a category', function (): void {
    $device = TestAuthority::create()->device(new AppId('ABCDE12345', 'com.example.app'), category: null);
    $assertion = Cbor::decode($device->assert('GET /me'));
    $authenticatorData = $assertion instanceof CborMap && $assertion->get('authenticatorData') instanceof ByteString ? $assertion->get('authenticatorData')->value : '';

    expect(strlen($authenticatorData))->toBe(37)
        ->and(ord($authenticatorData[32]))->toBe(0x40);
});
