# App Attest PHP

Verify [Apple App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) attestations and assertions on a PHP server. PHP `^8.3` with `ext-openssl`, and no other dependencies.

The package follows Apple's [server validation steps](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server). It passes Apple's [sample attestation](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide) against the pinned Apple App Attestation Root CA.

## Install

```bash
composer require jewei/app-attest-php
```

## Verify an attestation

The app creates a key with `DCAppAttestService.generateKey()` and attests it with `attestKey(_:clientDataHash:)`. Give the app a one-time challenge first, and have it pass `SHA256(challenge)` as `clientDataHash`.

```php
use AppAttest\AppId;
use AppAttest\Environment;
use AppAttest\Exception\VerificationException;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

$verifier = new Verifier(
    new AppId('ABCDE12345', 'com.example.app'), // App ID prefix (team ID) and bundle ID
    Environment::Production,
    allowedCategories: [ValidationCategory::AppStore, ValidationCategory::TestFlight], // optional
);

try {
    $key = $verifier->verifyAttestation(
        attestation: base64_decode($request->attestation, true),
        keyId: base64_decode($request->keyId, true),
        clientDataHash: hash('sha256', $challenge, true), // computed on the server
    );
} catch (VerificationException $exception) {
    // $exception->failure is an AppAttest\Exception\Failure, for example Failure::NonceMismatch.
}

// Store for this device: $key->keyId, $key->publicKey (PEM), counter 0, and $key->receipt.
```

## Verify an assertion

The app signs each request with `generateAssertion(_:clientDataHash:)`, where `clientDataHash` is `SHA256(clientData)`. Rebuild `clientData` on the server from the request and your one-time challenge.

```php
$assertion = $verifier->verifyAssertion(
    assertion: base64_decode($request->assertion, true),
    clientData: $clientData,
    publicKey: $stored->publicKey,
    previousCounter: $stored->counter,
);

// Store $assertion->counter in the same transaction that read $stored->counter.
```

## What your server still does

The package checks the cryptography and the data. Your server must also:

- Issue each challenge once, keep it short-lived, and delete it when it is used.
- Bind the challenge, the request, and the session into `clientData`, so that an assertion is valid for one request only.
- Read and update the stored counter atomically (for example, a row lock). Two requests with the same counter must not both pass.
- Refuse a key ID that another account already uses.
- Keep development and production keys apart.
- Verify the receipt and request the fraud risk metric yourself, if you use it. The package returns the receipt bytes and does not check them.

## Checks

`verifyAttestation()`:

1. The object is CBOR with exactly `fmt`, `attStmt` (`x5c`, `receipt`), and `authData`; `fmt` is `apple-appattest`.
2. `x5c` is the credential certificate and one intermediate. Each signature, issuer name, and validity period is checked up to the trust anchor. The intermediate is a CA that may sign certificates; the credential certificate is not a CA. A critical extension other than basic constraints or key usage is refused.
3. The nonce extension (OID `1.2.840.113635.100.8.2`) equals `SHA256(authData || clientDataHash)`.
4. `SHA256` of the credential key as an X9.62 uncompressed point equals the key ID. The key is EC P-256.
5. The RP ID hash equals `SHA256` of the App ID.
6. The counter is 0.
7. The AAGUID is `appattest` followed by seven zero bytes (production) or `appattestdevelop` (development).
8. The credential ID equals the key ID.
9. The validation category passes the policy.

`verifyAssertion()`:

1. The object is CBOR with exactly `signature` and `authenticatorData`.
2. The signature is ECDSA with SHA-256 over `nonce = SHA256(authenticatorData || SHA256(clientData))`, with the stored key.
3. The RP ID hash equals `SHA256` of the App ID.
4. The counter is above the stored counter.
5. The validation category passes the policy.

## Validation categories

Recent iOS versions add `apple_validation_category_01` and `apple_bundle_version_01` to the authenticator data. Both results expose them as `validationCategory` (a `ValidationCategory`, or null) and `bundleVersion` (a string, or null).

| Policy | Result |
| --- | --- |
| `allowedCategories: null` (default) | Accepts every category that `ValidationCategory` names, and a missing one. |
| `allowedCategories: [...]` | Accepts only the listed categories. A missing category fails. |

The verifier always refuses 0 (invalid), 7 to 9 (not appropriate for apps), and values that `ValidationCategory` does not name yet.

## Failures

A failed check throws `AppAttest\Exception\VerificationException`. Its `failure` property tells which check failed, with a stable string value for logs:

| Failure | Value |
| --- | --- |
| `MalformedInput` | `malformed_input` |
| `UnsupportedFormat` | `unsupported_format` |
| `InvalidCertificate` | `invalid_certificate` |
| `NonceMismatch` | `nonce_mismatch` |
| `KeyIdMismatch` | `key_id_mismatch` |
| `AppIdMismatch` | `app_id_mismatch` |
| `NonZeroCounter` | `non_zero_counter` |
| `EnvironmentMismatch` | `environment_mismatch` |
| `CredentialIdMismatch` | `credential_id_mismatch` |
| `CategoryNotAllowed` | `category_not_allowed` |
| `InvalidSignature` | `invalid_signature` |
| `CounterNotIncreased` | `counter_not_increased` |

Do not show the failure or the message to the client. A wrong argument from your own server, such as a stored public key that is not an EC P-256 PEM, throws `InvalidArgumentException`.

## Limits

- Attestations up to 32 KB and assertions up to 4 KB (`Verifier::MAX_ATTESTATION_BYTES`, `Verifier::MAX_ASSERTION_BYTES`).
- The CBOR decoder accepts only definite-length integers, byte strings, text strings, arrays, and maps, with at most 8 levels and 64 entries per container.
- iOS and iPadOS keys. macOS App Attest (code signing requirement RP ID and the `aclBlob` check) is not supported.

## Trust anchor

`resources/apple-app-attestation-root-ca.pem` is Apple's App Attestation Root CA, valid until 2045-03-15. [spec/provenance.json](spec/provenance.json) records its source and hashes. The `trustAnchor` constructor argument exists for tests; do not use it in production.

## Development

```bash
composer test           # architecture check, PHPStan, and Pest
composer test:mutation  # needs a coverage driver (pcov or Xdebug)
vendor/bin/pint --test
```

## License

MIT. See [LICENSE](LICENSE).
