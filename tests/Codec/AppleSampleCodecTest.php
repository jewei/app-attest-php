<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Internal\AuthenticatorData;
use AppAttest\Internal\ByteString;
use AppAttest\Internal\Cbor;
use AppAttest\Internal\CborMap;
use AppAttest\Internal\Der;

/** @return array{x5c: list<string>, authData: string, sample: array<string, mixed>} */
function decodedAppleSample(): array
{
    $sample = loadSpec('apple-sample-attestation.json');
    $object = Cbor::decode((string) base64_decode(specString($sample, 'attestation'), true));
    $statement = $object instanceof CborMap ? $object->get('attStmt') : null;
    $x5c = $statement instanceof CborMap ? $statement->get('x5c') : null;
    $authData = $object instanceof CborMap ? $object->get('authData') : null;

    if (! is_array($x5c) || ! $authData instanceof ByteString) {
        throw new \RuntimeException('The sample attestation does not have x5c and authData.');
    }

    $certificates = [];

    foreach ($x5c as $certificate) {
        $certificates[] = $certificate instanceof ByteString ? $certificate->value : throw new \RuntimeException('A certificate is not bytes.');
    }

    return ['x5c' => $certificates, 'authData' => $authData->value, 'sample' => $sample];
}

it('decodes the values that Apple\'s guide publishes for each step', function (): void {
    ['x5c' => $x5c, 'authData' => $authData, 'sample' => $sample] = decodedAppleSample();
    $expected = specObject($sample, 'expected');
    $clientDataHash = specString($sample, 'clientDataHash');
    $data = AuthenticatorData::attestation($authData);

    expect(base64_encode($x5c[0]))->toBe(specString($expected, 'leafCertificate'))
        ->and(base64_encode($x5c[1]))->toBe(specString($expected, 'intermediateCertificate'))
        ->and(base64_encode(hash('sha256', $authData.$clientDataHash, true)))->toBe(specString($expected, 'nonce'))
        ->and(base64_encode(Der::nonce((string) Der::extensionValue(Der::certificate($x5c[0])['extensions'], "\x2A\x86\x48\x86\xF7\x63\x64\x08\x02"))))->toBe(specString($expected, 'nonce'))
        ->and(base64_encode($data->rpIdHash))->toBe(specString($expected, 'rpIdHash'))
        ->and(base64_encode((new AppId('1234567890', 'com.example.myapp'))->hash()))->toBe(specString($expected, 'rpIdHash'))
        ->and($data->counter)->toBe($expected['counter'])
        ->and(bin2hex($data->aaguid))->toBe(specString($expected, 'aaguid'))
        ->and(base64_encode($data->credentialId))->toBe(specString($expected, 'credentialId'))
        ->and($data->validationCategory)->toBe($expected['validationCategory'])
        ->and($data->bundleVersion)->toBe(specString($expected, 'bundleVersion'));
});

it('reads the critical flags of the sample certificates', function (): void {
    ['x5c' => $x5c] = decodedAppleSample();

    $critical = static fn (string $der): array => array_values(array_map(
        static fn (array $extension): string => bin2hex($extension['oid']),
        array_filter(Der::certificate($der)['extensions'], static fn (array $extension): bool => $extension['critical']),
    ));

    expect($critical($x5c[0]))->toBe(['551d13', '551d0f'])
        ->and($critical($x5c[1]))->toBe(['551d13', '551d0f']);
});

it('reads the validity and names of the sample certificates', function (): void {
    ['x5c' => $x5c] = decodedAppleSample();
    $credential = Der::certificate($x5c[0]);
    $intermediate = Der::certificate($x5c[1]);

    expect($credential['notBefore'])->toBe((new \DateTimeImmutable('2026-04-20T18:13:12Z'))->getTimestamp())
        ->and($credential['notAfter'])->toBe((new \DateTimeImmutable('2026-04-23T18:13:12Z'))->getTimestamp())
        ->and($intermediate['notAfter'])->toBe((new \DateTimeImmutable('2030-03-13T00:00:00Z'))->getTimestamp())
        ->and($credential['issuer'])->toBe($intermediate['subject'])
        ->and(Der::basicConstraints((string) Der::extensionValue($intermediate['extensions'], Der::BASIC_CONSTRAINTS)))->toBe(['ca' => true, 'pathLength' => 0])
        ->and(Der::allowsCertificateSigning((string) Der::extensionValue($intermediate['extensions'], Der::KEY_USAGE)))->toBeTrue()
        ->and(Der::basicConstraints((string) Der::extensionValue($credential['extensions'], Der::BASIC_CONSTRAINTS)))->toBe(['ca' => false, 'pathLength' => null]);
});
