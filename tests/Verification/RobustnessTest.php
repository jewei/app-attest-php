<?php

declare(strict_types=1);

use AppAttest\Tests\Support\TestAuthority;

/**
 * Untrusted bytes may fail only with VerificationException. PHPUnit's
 * failOnWarning setting also fails the run on any PHP warning or notice.
 */
it('refuses every truncation of a valid attestation', function (): void {
    $attestation = testAttestation();
    $verifier = testVerifier();

    for ($length = 0; $length < strlen($attestation['attestation']); $length++) {
        expect(failureOf(fn () => $verifier->verifyAttestation(substr($attestation['attestation'], 0, $length), $attestation['keyId'], testClientDataHash())))
            ->not->toBeNull();
    }
});

it('refuses a change to any byte outside the receipt', function (): void {
    $attestation = testAttestation();
    $object = $attestation['attestation'];
    $receipt = strpos($object, 'test receipt');
    expect($receipt)->toBeInt();
    $verifier = testVerifier();

    for ($index = 0; $index < strlen($object); $index++) {
        $changed = $object;
        $changed[$index] = chr(ord($changed[$index]) ^ 0x01);
        $failure = failureOf(fn () => $verifier->verifyAttestation($changed, $attestation['keyId'], testClientDataHash()));
        $inReceipt = $index >= $receipt && $index < $receipt + strlen('test receipt');

        expect($failure === null)->toBe($inReceipt, "Byte {$index}");
    }
});

it('refuses every truncation of Apple\'s sample attestation', function (): void {
    $sample = appleSample();

    for ($length = 0; $length < strlen($sample['attestation']); $length++) {
        expect(failureOf(fn () => $sample['verifier']->verifyAttestation(substr($sample['attestation'], 0, $length), $sample['keyId'], $sample['clientDataHash'], $sample['at'])))
            ->not->toBeNull();
    }
});

it('refuses every truncation of and every change to a valid assertion', function (): void {
    $key = attestedKey();
    $assertion = TestAuthority::assertion($key['key'], testAppId(), 'client data', 9);
    $verifier = testVerifier();
    expect(failureOf(fn () => $verifier->verifyAssertion($assertion, 'client data', $key['publicKey'], 8)))->toBeNull();

    for ($index = 0; $index < strlen($assertion); $index++) {
        $changed = $assertion;
        $changed[$index] = chr(ord($changed[$index]) ^ 0x01);

        expect(failureOf(fn () => $verifier->verifyAssertion(substr($assertion, 0, $index), 'client data', $key['publicKey'], 8)))->not->toBeNull()
            ->and(failureOf(fn () => $verifier->verifyAssertion($changed, 'client data', $key['publicKey'], 8)))->not->toBeNull("Byte {$index}");
    }
});

it('refuses random bytes', function (): void {
    $verifier = testVerifier();
    $publicKey = attestedKey()['publicKey'];
    mt_srand(20261011);

    for ($run = 0; $run < 500; $run++) {
        $bytes = '';

        for ($length = mt_rand(1, 300); $length > 0; $length--) {
            $bytes .= chr(mt_rand(0, 255));
        }

        expect(failureOf(fn () => $verifier->verifyAttestation($bytes, str_repeat("\0", 32), testClientDataHash())))->not->toBeNull()
            ->and(failureOf(fn () => $verifier->verifyAssertion($bytes, 'x', $publicKey, 0)))->not->toBeNull();
    }
});
