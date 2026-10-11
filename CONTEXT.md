# App Attest terminology

This glossary defines the terms in the source, tests, and README. The terms follow Apple's [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) and WebAuthn's authenticator data.

### App ID

The App ID prefix (usually the 10-character team ID), a period, and the bundle ID. Example: `ABCDE12345.com.example.app`.

### RP ID hash

The first 32 bytes of the authenticator data: SHA-256 of the App ID.

### Key ID

The identifier that `generateKey()` returns, Base64 in the app. It is SHA-256 of the key's public key as an X9.62 uncompressed point (`0x04 || X || Y`, 65 bytes). The package takes and returns the raw 32 bytes.

### Credential ID

The key identifier inside an attestation's authenticator data. It must equal the key ID.

### Client data hash

The bytes that the app passes to `attestKey()` or `generateAssertion()`. For an attestation, the server's one-time challenge or its SHA-256. For an assertion, SHA-256 of the client data.

### Client data

The request data that the app hashes for an assertion. The server rebuilds it from the request.

### Nonce

For an attestation: SHA-256(authData || clientDataHash), stored in the credential certificate extension `1.2.840.113635.100.8.2`. For an assertion: SHA-256(authenticatorData || SHA-256(clientData)); the device signs it with ECDSA-SHA-256.

### Credential certificate

The first certificate in `x5c`. It holds the attested public key and the nonce.

### Trust anchor

The root certificate that ends the chain: Apple's App Attestation Root CA, pinned in `resources/`.

### AAGUID

16 bytes in an attestation's authenticator data that name the environment: `appattest` and seven zero bytes (production), or `appattestdevelop` (development).

### Counter

A 32-bit counter in the authenticator data. It is 0 in an attestation and increases with each assertion.

### Validation category

The `apple_validation_category_01` extension: how the app's code is signed, for example for TestFlight or the App Store. Apple writes it as 4 little-endian bytes.

### Receipt

Bytes in the attestation statement that the server can send to Apple to get a fraud risk metric. The package returns them and does not verify them.

### ED flag

Bit 7 of the authenticator data flags: extensions follow the counter. Assertions with extensions set it; Apple's attestations do not.

### Platform field

Field `[1026]` of the certificate extension `1.2.840.113635.100.8.7`: the platform that made the key, for example `iphoneos`.

### aclBlob

The certificate extension `1.2.840.113635.100.8.6`: the key's access-control policy, from the 2026 OS releases. On macOS it requires full security mode and System Integrity Protection; a Mac with System Integrity Protection off writes another value.

### Environment

`production` or `development` App Attest (the app's entitlement). The AAGUID names it, and a key works only in its own environment.
