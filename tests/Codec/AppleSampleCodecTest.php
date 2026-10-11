<?php

declare(strict_types=1);

use AppAttest\AppId;
use AppAttest\Internal\AuthenticatorData;
use AppAttest\Internal\ByteString;
use AppAttest\Internal\Cbor;
use AppAttest\Internal\Der;

/** @return array{x5c: list<string>, authData: string, sample: array<string, mixed>} */
function decodedAppleSample(): array
{
    $sample = loadSpec('apple-sample-attestation.json');
    $object = Cbor::decode((string) base64_decode(specString($sample, 'attestation'), true));
    $statement = is_array($object) ? ($object['attStmt'] ?? null) : null;
    $x5c = is_array($statement) ? ($statement['x5c'] ?? null) : null;
    $authData = is_array($object) ? ($object['authData'] ?? null) : null;

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
        ->and(base64_encode(Der::nonce(Der::extensions($x5c[0])["\x2A\x86\x48\x86\xF7\x63\x64\x08\x02"]['value'])))->toBe(specString($expected, 'nonce'))
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

    $critical = static fn (string $der): array => array_map(
        static fn (string $oid): string => bin2hex($oid),
        array_keys(array_filter(Der::extensions($der), static fn (array $extension): bool => $extension['critical'])),
    );

    expect($critical($x5c[0]))->toBe(['551d13', '551d0f'])
        ->and($critical($x5c[1]))->toBe(['551d13', '551d0f']);
});
