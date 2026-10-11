<?php

declare(strict_types=1);

namespace AppAttest\Testing;

use AppAttest\AppId;
use AppAttest\Environment;
use AppAttest\ValidationCategory;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * A test device: one P-256 key that attests and signs assertions as App Attest does,
 * with an assertion counter that increases by one for each assertion.
 *
 * For tests only. Create it with TestAuthority::device().
 */
final class TestDevice
{
    /** The key ID (raw 32 bytes; the app sends its Base64). */
    public readonly string $keyId;

    private int $counter = 0;

    private readonly string $point;

    /** @internal Created by TestAuthority::device(). */
    public function __construct(
        private readonly TestAuthority $authority,
        private readonly OpenSSLAsymmetricKey $key,
        private readonly AppId $appId,
        private readonly Environment $environment,
        private readonly ?ValidationCategory $category,
        private readonly string $bundleVersion,
    ) {
        $details = openssl_pkey_get_details($key);
        $x = is_array($details) && is_array($details['ec'] ?? null) && is_string($details['ec']['x'] ?? null) ? $details['ec']['x'] : '';
        $y = is_array($details) && is_array($details['ec'] ?? null) && is_string($details['ec']['y'] ?? null) ? $details['ec']['y'] : '';
        $this->point = "\x04".str_pad($x, 32, "\0", STR_PAD_LEFT).str_pad($y, 32, "\0", STR_PAD_LEFT);
        $this->keyId = hash('sha256', $this->point, true);
    }

    /** The attestation object (raw CBOR) for $clientDataHash, as attestKey() returns it. */
    public function attest(string $clientDataHash): string
    {
        $authData = $this->appId->hash()."\x40\x00\x00\x00\x00".$this->environment->aaguid()
            .pack('n', 32).$this->keyId
            .Cbor::map([1 => 2, 3 => -7, -1 => 1, -2 => Cbor::bytes(substr($this->point, 1, 32)), -3 => Cbor::bytes(substr($this->point, 33, 32))])
            .$this->extensions();
        [$credential, $intermediate] = $this->authority->issue($this->key, $this->keyId, hash('sha256', $authData.$clientDataHash, true));

        return Cbor::map([
            'fmt' => Cbor::text('apple-appattest'),
            'attStmt' => Cbor::map(['x5c' => Cbor::array([Cbor::bytes($credential), Cbor::bytes($intermediate)]), 'receipt' => Cbor::bytes('test receipt')]),
            'authData' => Cbor::bytes($authData),
        ]);
    }

    /** The next assertion object (raw CBOR) for $clientData, as generateAssertion(SHA256(clientData)) returns it. */
    public function assert(string $clientData): string
    {
        $this->counter++;
        $authenticatorData = $this->appId->hash()."\x40".pack('N', $this->counter).$this->extensions();
        $nonce = hash('sha256', $authenticatorData.hash('sha256', $clientData, true), true);

        if (! openssl_sign($nonce, $signature, $this->key, OPENSSL_ALGO_SHA256) || ! is_string($signature)) {
            throw new RuntimeException('openssl_sign failed.');
        }

        return Cbor::map(['signature' => Cbor::bytes($signature), 'authenticatorData' => Cbor::bytes($authenticatorData)]);
    }

    /** The counter of the last assertion. */
    public function counter(): int
    {
        return $this->counter;
    }

    private function extensions(): string
    {
        if ($this->category === null) {
            return '';
        }

        return Cbor::map([
            'apple_bundle_version_01' => Cbor::text($this->bundleVersion),
            'apple_validation_category_01' => Cbor::bytes(pack('V', $this->category->value)),
        ]);
    }
}
