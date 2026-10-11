# App Attest PHP

Verify [Apple App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) attestations and assertions on a PHP server. 64-bit PHP `^8.3` with `ext-openssl`, and no other dependencies.

The package follows Apple's [server validation steps](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server). It passes Apple's [sample attestation](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide) against the pinned Apple App Attestation Root CA, and a real iOS 27 assertion.

## Install

```bash
composer require jewei/app-attest-php
```

## Create a verifier

```php
use AppAttest\AppId;
use AppAttest\CategoryPolicy;
use AppAttest\Environment;
use AppAttest\ValidationCategory;
use AppAttest\Verifier;

$verifier = new Verifier(
    new AppId('ABCDE12345', 'com.example.app'), // App ID prefix (team ID) and bundle ID
    Environment::Production,                     // from your server configuration
    CategoryPolicy::only(ValidationCategory::AppStore, ValidationCategory::TestFlight),
);
```

The [category policy](#validation-categories) is required.

## Verify an attestation

The app creates a key with `DCAppAttestService.generateKey()` and attests it with `attestKey(_:clientDataHash:)`. Give the app a one-time challenge first, and have it pass `SHA256(challenge)` as `clientDataHash`.

```php
use AppAttest\Exception\VerificationException;

$attestation = base64_decode($request->attestation, true);
$keyId = base64_decode($request->keyId, true);

if ($attestation === false || $keyId === false) {
    return refuse(); // not Base64
}

try {
    $key = $verifier->verifyAttestation(
        attestation: $attestation,
        keyId: $keyId,
        clientDataHash: hash('sha256', $challenge, true), // your stored challenge, not a value from the request
    );
} catch (VerificationException $exception) {
    log_refusal($exception->failure->value); // for example "nonce_mismatch"

    return refuse();
}

// Store for this device: $key->keyId, $key->publicKey (PEM), $key->environment, counter 0, and $key->receipt.
```

## Verify an assertion

The app signs each request with `generateAssertion(_:clientDataHash:)`, where `clientDataHash` is `SHA256(clientData)`. Rebuild `clientData` on the server from the request and your one-time challenge.

```php
try {
    $assertion = $verifier->verifyAssertion(
        assertion: $assertionBytes, // decoded from Base64 as above
        clientData: $clientData,
        publicKey: $stored->publicKey,
        previousCounter: $stored->counter,
        keyEnvironment: $stored->environment, // the key's stored environment
    );
} catch (VerificationException $exception) {
    return refuse();
}

// Store $assertion->counter in the same transaction that read $stored->counter.
```

## What your server still does

The package checks the cryptography and the data. Your server must also:

- Issue each challenge once, keep it short-lived, and delete it when it is used.
- Bind the challenge, the request, and the session into `clientData`, so that an assertion is valid for one request only.
- Read and update the stored counter atomically (for example, a row lock). The counter is the replay guard: an ECDSA signature can be changed into another valid signature for the same data, so do not use the assertion bytes as a replay key.
- Store each key's environment with it, and pass it back as `keyEnvironment`. Build the verifier's environment from your server configuration, never from the stored key, so that a development key cannot pass a production verifier.
- Refuse a key ID that another account already uses.
- Check `bundleVersion` if you need a minimum app version. The package returns it and does not compare versions.
- Verify the receipt and request the fraud risk metric yourself, if you use it. The package returns the receipt bytes and does not check them.

## Checks

`verifyAttestation()`:

1. The object is CBOR with exactly `fmt`, `attStmt` (`x5c`, `receipt`), and `authData`; `fmt` is `apple-appattest`.
2. `x5c` is an array of the credential certificate and one intermediate. The intermediate has neither the anchor's key nor the same issuer and subject. The credential key is EC P-256 and the intermediate key EC P-256 or P-384, checked before OpenSSL reads any key. The issuer and subject names match byte for byte. The anchor signed the intermediate, and the intermediate signed the credential certificate. All three are valid at the check time. The intermediate is a CA with `keyCertSign`; the credential certificate is not a CA. A critical extension other than basic constraints or key usage is refused. Flags, names, and times are read from DER that is strict for the fields that the package reads (version 3, the outer signature algorithm equal to the signed one, no written DEFAULT values, minimal keyUsage bits), and times must have the RFC 5280 forms: UTCTime through 2049, GeneralizedTime from 2050.
3. The nonce extension (OID `1.2.840.113635.100.8.2`) equals `SHA256(authData || clientDataHash)`. A platform field in extension `1.2.840.113635.100.8.7` other than `iphoneos` is refused; this field is the macOS guard. Apple's documented macOS access-control blob in extension `1.2.840.113635.100.8.6` is refused too, but other macOS blobs are not recognised, so a certificate without the platform field depends on Apple writing it for every Mac key.
4. `SHA256` of the credential key as an X9.62 uncompressed point equals the key ID. The key is EC P-256.
5. The RP ID hash equals `SHA256` of the App ID.
6. The counter is 0.
7. The AAGUID is `appattest` followed by seven zero bytes (production) or `appattestdevelop` (development).
8. The credential ID equals the key ID.
9. The validation category passes the policy.

`verifyAssertion()`:

1. The stored key's environment is the verifier's environment. The object is CBOR with exactly `signature` and `authenticatorData`. The ED flag must match the bytes after the counter: with it, an extensions map; without it, nothing.
2. The signature is ECDSA with SHA-256 over `nonce = SHA256(authenticatorData || SHA256(clientData))`, with the stored key.
3. The RP ID hash equals `SHA256` of the App ID.
4. The counter is above the stored counter.
5. The validation category passes the policy.

## Validation categories

Apple's current documentation adds `apple_validation_category_01` (how the app was distributed) and `apple_bundle_version_01` to the authenticator data. (Its assertion steps call them `validationCategory` and `bundleVersion`; the real assertion in `spec/` uses the `_01` keys, so the package reads those.) Apple's sample attestation and the real iOS 27 assertion in `spec/` have both; devices on older iOS versions may not write them. Both results expose them as `validationCategory` (a `ValidationCategory`, or null) and `bundleVersion` (a string, or null).

| Policy | Result |
| --- | --- |
| `CategoryPolicy::only(...)` | Only the listed categories. A missing category fails, so devices that do not write one are refused. |
| `CategoryPolicy::onlyOrMissing(...)` | The listed categories, or none (devices on older iOS versions). |
| `CategoryPolicy::any()` | Every category that `ValidationCategory` names, including `Development` and `DeveloperId`, and a missing one. |

The verifier always refuses 0 (invalid), 7 to 9 (not appropriate for apps), and values that `ValidationCategory` does not name yet.

The app chooses the client data hash, and nothing in the signed bytes marks where the authenticator data ends. In an assertion the ED flag closes that gap. Apple's attestations do not set the ED flag, so on a device that writes no extensions, a modified app can make an attestation carry any category. The verifier checks the policy again on every assertion, where it cannot be forged, so base your decisions on assertions; treat the attestation's category and bundle version as a hint.

## Failures

A failed check throws `AppAttest\Exception\VerificationException`. Its `failure` property tells which check failed, with a stable string value for logs:

| Failure | Value |
| --- | --- |
| `MalformedInput` | `malformed_input` |
| `UnsupportedFormat` | `unsupported_format` |
| `UnsupportedPlatform` | `unsupported_platform` |
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

New `Failure` and `ValidationCategory` cases can come in minor versions, so give a `match` on them a default arm. An upgrade that names a new category widens `CategoryPolicy::any()`.

Do not show the failure or the message to the client. A wrong argument from your own server, such as a stored public key that is not an EC P-256 PEM, throws `InvalidArgumentException`.

The package empties OpenSSL's error queue (`openssl_error_string()`) after its calls. OpenSSL cannot keep earlier entries, so read the queue before you call the verifier if you need it.

## Limits

- 64-bit PHP only: Composer requires `php-64bit`, and the constructor refuses a 32-bit build.
- Attestations up to 32 KB and assertions up to 4 KB (`Verifier::MAX_ATTESTATION_BYTES`, `Verifier::MAX_ASSERTION_BYTES`).
- The CBOR decoder accepts only definite-length integers, byte strings, text strings, arrays, maps, false, true, and null, with at most 8 levels and 64 entries per container. It accepts a length or integer in a longer form than needed, because the value is the same and the signed data is hashed as raw bytes.
- iPhone and iPad keys only. A key whose certificate names another platform, such as macOS, is refused (`UnsupportedPlatform`): on macOS the RP ID uses the signing identifier, and Apple requires an `aclBlob` check that this package does not make. Certificates without the platform field are accepted. Tests use iOS data.

## Test your integration

`AppAttest\Testing` makes real attestations and assertions without a device, so your own tests can run the whole flow. For tests only: never pass its root to a production verifier.

```php
use AppAttest\Testing\TestAuthority;

$appId = new AppId('ABCDE12345', 'com.example.app');
$authority = TestAuthority::create();
$device = $authority->device($appId, Environment::Production, ValidationCategory::TestFlight);
$verifier = new Verifier($appId, Environment::Production, CategoryPolicy::only(ValidationCategory::TestFlight), $authority->rootPem());

$attestation = $device->attest(hash('sha256', $challenge, true)); // send with base64_encode($device->keyId)
$assertion = $device->assert($clientData);                        // the counter increases with each call
```

The test certificates are valid for 3 days from `TestAuthority::create()` and `attest()`. A test that freezes the clock must keep it inside that window, or pass the time to `verifyAttestation()`.

## Trust anchor

`resources/apple-app-attestation-root-ca.pem` is Apple's App Attestation Root CA, valid until 2045-03-15. [spec/provenance.json](https://github.com/jewei/app-attest-php/blob/main/spec/provenance.json) records its source and hashes. The `trustAnchor` constructor argument is for tests with `AppAttest\Testing` or your own test CA; do not set it in production.

## Development

```bash
composer test           # architecture check, PHPStan, and Pest
composer test:mutation  # needs a coverage driver (pcov or Xdebug)
vendor/bin/pint --test
```

## License

MIT. See [LICENSE](LICENSE). [spec/third-party](https://github.com/jewei/app-attest-php/tree/main/spec/third-party) has a test fixture under the Apache License 2.0.
