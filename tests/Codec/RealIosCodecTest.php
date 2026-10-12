<?php

declare(strict_types=1);

use AppAttest\Internal\ByteString;
use AppAttest\Internal\Cbor;
use AppAttest\Internal\CborMap;
use AppAttest\Internal\Der;

/** @return array{object: CborMap, certificate: array{issuer: string, subject: string, publicKey: string, curve: ?string, notBefore: int, notAfter: int, extensions: list<array{oid: string, critical: bool, value: string}>}} */
function realIosObject(): array
{
    $object = Cbor::decode((string) base64_decode(specString(loadSpec('termakan-ios27-attestation.json'), 'attestation'), true));
    $statement = $object instanceof CborMap ? $object->get('attStmt') : null;
    $x5c = $statement instanceof CborMap ? $statement->get('x5c') : null;

    if (! $object instanceof CborMap || ! is_array($x5c) || ! $x5c[0] instanceof ByteString) {
        throw new \RuntimeException('The real iOS attestation has no credential certificate.');
    }

    return ['object' => $object, 'certificate' => Der::certificate($x5c[0]->value)];
}

it('reads iphoneos and an access-control blob that is not the macOS blob from the real iOS 27.0.1 certificate', function (): void {
    $extensions = realIosObject()['certificate']['extensions'];
    $platform = Der::extensionValue($extensions, "\x2A\x86\x48\x86\xF7\x63\x64\x08\x07");
    $acl = Der::extensionValue($extensions, "\x2A\x86\x48\x86\xF7\x63\x64\x08\x06");
    $macAcl = (string) base64_decode('MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB', true);

    expect($platform === null ? null : Der::platform($platform))->toBe('iphoneos')
        ->and($acl)->not->toBeNull()
        ->and($acl !== null && str_contains($acl, $macAcl))->toBeFalse();
});

it('reads the ED flag in the real iOS attestation and both real assertions', function (): void {
    $authData = realIosObject()['object']->get('authData');
    $flags = [$authData instanceof ByteString ? ord($authData->value[32]) : null];
    $items = loadSpec('termakan-ios27-attestation.json')['assertions'] ?? null;

    foreach (is_array($items) ? $items : [] as $item) {
        $item = stringKeyed(is_array($item) ? $item : [], 'assertions');
        $assertion = Cbor::decode((string) base64_decode(specString($item, 'assertion'), true));
        $data = $assertion instanceof CborMap ? $assertion->get('authenticatorData') : null;
        $flags[] = $data instanceof ByteString ? ord($data->value[32]) : null;
    }

    // Apple's 2026 sample attestation writes 0x40; real iOS 27 and macOS 27 attestations write 0xC0.
    expect($flags)->toBe([0xC0, 0xC0, 0xC0]);
});
