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
        /** The receipt for Apple's fraud risk metric (raw bytes). */
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
