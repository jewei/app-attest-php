<?php

declare(strict_types=1);

namespace AppAttest;

/** An assertion that passed verification. Store `$counter` for the next one. */
final readonly class VerifiedAssertion
{
    /** @internal Created by Verifier::verifyAssertion(). */
    public function __construct(
        public int $counter,
        /** Null when the authenticator data has no `apple_validation_category_01`. */
        public ?ValidationCategory $validationCategory,
        /** `apple_bundle_version_01`, or null when absent. */
        public ?string $bundleVersion,
    ) {}
}
