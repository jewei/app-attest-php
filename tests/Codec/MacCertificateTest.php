<?php

declare(strict_types=1);

use AppAttest\Internal\ByteString;
use AppAttest\Internal\Cbor;
use AppAttest\Internal\CborMap;
use AppAttest\Internal\Der;

it('reads macosx and Apple\'s documented macOS access-control blob from the real macOS certificate', function (): void {
    $object = Cbor::decode((string) base64_decode(specString(loadSpec('third-party/arkavo-macos27-attestation.json'), 'attestation_object'), true));
    $statement = $object instanceof CborMap ? $object->get('attStmt') : null;
    $x5c = $statement instanceof CborMap ? $statement->get('x5c') : null;
    $certificate = is_array($x5c) && $x5c[0] instanceof ByteString ? Der::certificate($x5c[0]->value) : null;
    $platform = $certificate === null ? null : Der::extensionValue($certificate['extensions'], "\x2A\x86\x48\x86\xF7\x63\x64\x08\x07");
    $acl = $certificate === null ? null : Der::extensionValue($certificate['extensions'], "\x2A\x86\x48\x86\xF7\x63\x64\x08\x06");
    $macAcl = (string) base64_decode('MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB', true);

    expect($platform === null ? null : Der::platform($platform))->toBe('macosx')
        ->and($acl !== null && str_contains($acl, $macAcl))->toBeTrue();
});
