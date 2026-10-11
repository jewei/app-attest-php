# App Attest PHP

Verify [Apple App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) attestations and assertions on a PHP server. 64-bit PHP `^8.3` with `ext-openssl`, and no other dependencies.

The package follows Apple's [server validation steps](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server). It passes Apple's [sample attestations](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide) of 2026 (iOS 27) and 2024 (iOS 18.0) against the pinned Apple App Attestation Root CA, and a real iOS 27 assertion.

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
    CategoryPolicy::onlyOrMissing(ValidationCategory::AppStore, ValidationCategory::TestFlight),
);
```

The [category policy](#validation-categories) is required. Devices write the category from iOS 27; iOS 26 and earlier write none (Apple, WWDC26 session 201). `onlyOrMissing()` accepts those devices without a category check. If your app needs iOS 27 or later, use the stricter `only()`, which refuses a device that writes no category, at attestation and at every assertion.

For an App Clip, use the full app's bundle ID: Apple builds the App Clip's RP ID from it. Write the bundle ID in the exact case of the app's entitlement: the RP ID hash is case-sensitive.

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

// Store for this device: $key->keyId, $key->publicKey (PEM), $key->environment->value, counter 0, and, if you use
// the fraud metric, $key->receipt (unverified: see below) and $key->certificate (each new receipt's field 3 must equal it).
```

The credential certificate is valid for 3 days (in Apple's samples, from 24 hours before the time in its serial number). Verify the attestation when the app sends it, and keep the server clock in sync (NTP).

## Verify an assertion

The app signs each request with `generateAssertion(_:clientDataHash:)`, where `clientDataHash` is `SHA256(clientData)`. Rebuild `clientData` on the server from the request and your one-time challenge.

```php
try {
    $assertion = $verifier->verifyAssertion(
        assertion: $assertionBytes, // decoded from Base64 as above
        clientData: $clientData,
        publicKey: $stored->publicKey,
        previousCounter: $stored->counter,
        keyEnvironment: Environment::from($stored->environment), // the key's stored environment
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
- Verify the receipt and request the fraud risk metric yourself, if you use it ([Assessing fraud risk](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk)). The package returns the receipt bytes and does not check them. The attestation does not sign the receipt, so an attacker can put in the receipt of another key. Before you store or use it, verify its signature chain to Apple Root CA - G3, then its fields: 2 is the App ID; 3 is the credential certificate, equal to `$key->certificate`; 4 is the client data hash that you passed; 12, the creation time, is no more than five minutes old.

## Checks

`verifyAttestation()`:

1. The object is CBOR with exactly `fmt`, `attStmt` (`x5c`, `receipt`), and `authData`; `fmt` is `apple-appattest`.
2. `x5c` is an array of the credential certificate and one intermediate. The intermediate has neither the anchor's key nor the same issuer and subject. The credential key is EC P-256 and the intermediate key EC P-256 or P-384, checked before OpenSSL reads any key. The issuer and subject names match byte for byte. The anchor signed the intermediate, and the intermediate signed the credential certificate. All three are valid at the check time. The intermediate is a CA with `keyCertSign`; the credential certificate is not a CA. A critical extension other than basic constraints or key usage is refused. Flags, names, and times are read from DER that is strict for the fields that the package reads (version 3, the outer signature algorithm equal to the signed one, no written DEFAULT values, minimal keyUsage bits), and times must have the RFC 5280 forms: UTCTime through 2049, GeneralizedTime from 2050.
3. The nonce extension (OID `1.2.840.113635.100.8.2`) equals `SHA256(authData || clientDataHash)`. A platform field in extension `1.2.840.113635.100.8.7` other than `iphoneos` is refused. Apple's documented macOS key access-control blob in extension `1.2.840.113635.100.8.6` is refused too: a Mac with full security mode and System Integrity Protection writes it (WWDC26 session 201). A Mac with System Integrity Protection off writes another blob, which the package cannot recognise, so a certificate with an access-control blob must also have the platform field (iOS 27 writes both); a certificate with neither (iOS 26 and earlier) is accepted.
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

Apple's current documentation adds `apple_validation_category_01` (how the app's code is signed) and `apple_bundle_version_01` to the authenticator data. (Its assertion steps call them `validationCategory` and `bundleVersion`; the real assertion in `spec/` uses the `_01` keys, so the package reads those.) Devices write them from iOS 27 (Apple, WWDC26 session 201); iOS 26 and earlier write neither. Apple's sample attestation (iOS 27) and the real iOS 27 assertion in `spec/` have both. Both results expose them as `validationCategory` (a `ValidationCategory`, or null) and `bundleVersion` (a string, or null).

| Policy | Result |
| --- | --- |
| `CategoryPolicy::only(...)` | Only the listed categories. A missing category fails, so devices on iOS 26 and earlier are refused. For apps that need iOS 27 or later. |
| `CategoryPolicy::onlyOrMissing(...)` | The listed categories, or none (devices on iOS 26 and earlier). |
| `CategoryPolicy::any()` | Every category that `ValidationCategory` names, and a missing one: also `OperatingSystem` (1) and `Other` (10), which point to a jailbroken device (1) or a re-signed or sideloaded app (10). (Apple's own 2026 sample reports 1, because it comes from an Apple-internal build.) For tests and diagnostics, not production. |

A third-party app that Apple distributes reports `AppStore` or `TestFlight`, and a build that Xcode runs with a development profile reports `Development`. The verifier always refuses 0 (invalid), 7 to 9 (Apple: binaries that the system generates in restricted situations, not appropriate), and values that `ValidationCategory` does not name yet.

The app chooses the client data hash, and nothing in the signed bytes marks where the authenticator data ends. In an assertion the ED flag closes that gap. Apple's 2026 sample attestation writes extensions without the ED flag (`0x40`), while real iOS 27 and macOS 27 attestations set it (`0xC0`), so the package cannot require the flag in attestations: it reads an attestation's extensions whenever bytes remain. So on a device that writes no extensions, a modified app can make an attestation carry any category. The verifier checks the policy again on every assertion, where the app cannot change it, so base your decisions on assertions; treat the attestation's category and bundle version as a hint.

Apple says that the extensions follow the WebAuthn authenticator data format (WWDC26 session 201), where the ED flag marks them; the rule above follows that and a real iOS 27 assertion (flags `0xC0` with extensions). If every assertion from one OS version fails with `malformed_input`, that version writes extensions without the flag: please [open an issue](https://github.com/jewei/app-attest-php/issues) with a sample. Remove user and session values from the client data first, or send the sample privately (see [SECURITY.md](SECURITY.md)).

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
- `x5c` must hold exactly the credential certificate and one intermediate, as Apple sends today. Apple's intermediate "Apple App Attestation CA 1" is valid until 2030-03-13; watch for a change in the chain before then.
- The package reads only the category and the bundle version from the authenticator data extensions, and ignores other keys (for example `apple_cd_hash_hash_01`, which a CDHash opt-in writes).
- `invalid_certificate` covers a forged or broken chain and also a certificate that is not valid at the check time (a late check or a wrong server clock).
- The platform extension `1.2.840.113635.100.8.7` is not in Apple's validation steps, and the package parses it strictly. If an OS update changes its layout, every key from that OS fails with `invalid_certificate`: please report it with a sample.
- The CBOR decoder accepts only definite-length integers, byte strings, text strings, arrays, maps, false, true, and null, with at most 8 levels and 64 entries per container. It accepts a length or integer in a longer form than needed, because the value is the same and the signed data is hashed as raw bytes.
- iPhone and iPad keys only. From the 2026 OS releases, App Attest works on all Apple platforms. Keys from macOS (also an iPad app on a Mac), tvOS, watchOS, and visionOS are refused with `UnsupportedPlatform` when their platform field is not `iphoneos`, when the key carries Apple's macOS access-control blob (a Mac with full security), or when it carries an access-control blob without a platform field. A Mac with System Integrity Protection off whose platform field says `iphoneos` would not be caught by these checks. Treat `unsupported_platform` as an unsupported device, not as proof of fraud. Certificates without the platform field are accepted. A real macOS 27.0 attestation in `spec/third-party/` confirms that a native Mac app writes `macosx` and Apple's documented blob. The values that tvOS, watchOS, visionOS, and an iPad app on a Mac or on visionOS write are not confirmed. If you must refuse Macs, also turn off the app's availability on Mac in App Store Connect.

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

The test root and intermediate are valid for 10 years from `TestAuthority::create()`; each credential certificate is valid for 3 days from `attest()`. A test that freezes the clock must keep it inside that window, or pass the time to `verifyAttestation()`.

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
