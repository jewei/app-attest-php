<?php

declare(strict_types=1);

namespace AppAttest;

/**
 * A key that passed attestation. Store it for the device, then verify the
 * device's assertions with `$publicKey`. The next assertion must have a counter
 * above 0.
 */
final readonly class AttestedKey
{
    /** @internal Created by Verifier::verifyAttestation(). */
    public function __construct(
        /** The 32-byte key ID (raw bytes; the app's key ID is its Base64). */
        public string $keyId,
        /** The public key as a PEM SubjectPublicKeyInfo. */
        public string $publicKey,
        /** The credential certificate (DER), which the receipt's field 3 must equal. */
        public string $certificate,
        /**
         * The receipt for Apple's fraud risk metric (raw bytes). Not verified: the attestation does not sign it, so
         * check its Apple signature (to Apple Root CA - G3), App ID (field 2), credential certificate (field 3, equal to
         * $certificate), client data hash (field 4), and creation time (field 12) before you store or use it.
         */
        public string $receipt,
        public Environment $environment,
        /**
         * Null when the authenticator data has no `apple_validation_category_01`. A hint only: on a device that
         * writes no extensions, a modified app can supply it. Every assertion checks the policy again.
         */
        public ?ValidationCategory $validationCategory,
        /** `apple_bundle_version_01`, or null when absent. A hint only, like the category. */
        public ?string $bundleVersion,
    ) {}
}
