<?php

declare(strict_types=1);

namespace AppAttest\Exception;

/** The check that refused an attestation or an assertion. The values are stable, for logs. */
enum Failure: string
{
    /** The input is too large, truncated, or not the CBOR structure that Apple defines. */
    case MalformedInput = 'malformed_input';
    /** The attestation format is not `apple-appattest`. */
    case UnsupportedFormat = 'unsupported_format';
    /** The credential certificate names a platform other than iPhone and iPad (`iphoneos`), such as macOS. */
    case UnsupportedPlatform = 'unsupported_platform';
    /**
     * A certificate is malformed; the chain does not lead to the trust anchor; a certificate is not valid at
     * the check time; a CA flag, key usage, or critical extension is wrong; the nonce extension is missing or
     * malformed; or the credential key is not EC P-256.
     */
    case InvalidCertificate = 'invalid_certificate';
    /** The credential certificate's nonce is not SHA-256(authData || clientDataHash). */
    case NonceMismatch = 'nonce_mismatch';
    /** SHA-256 of the credential certificate's public key is not the key ID. */
    case KeyIdMismatch = 'key_id_mismatch';
    /** The RP ID hash is not SHA-256 of the App ID. */
    case AppIdMismatch = 'app_id_mismatch';
    /** An attestation's counter is not 0. */
    case NonZeroCounter = 'non_zero_counter';
    /** The AAGUID is not the one for the expected environment, or a stored key is from another environment. */
    case EnvironmentMismatch = 'environment_mismatch';
    /** The credential ID is not the key ID. */
    case CredentialIdMismatch = 'credential_id_mismatch';
    /** The validation category is refused, unknown, or missing when categories are required. */
    case CategoryNotAllowed = 'category_not_allowed';
    /** The assertion signature is not valid for the nonce and the stored public key. */
    case InvalidSignature = 'invalid_signature';
    /** The assertion counter is not above the stored counter. */
    case CounterNotIncreased = 'counter_not_increased';
}
