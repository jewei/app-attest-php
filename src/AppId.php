<?php

declare(strict_types=1);

namespace AppAttest;

use InvalidArgumentException;
use Stringable;

/**
 * An App ID: the App ID prefix (usually the team ID), a period, and the bundle ID.
 *
 * App Attest writes the SHA-256 of this string as the RP ID hash in every
 * attestation and assertion.
 */
final readonly class AppId implements Stringable
{
    public function __construct(public string $prefix, public string $bundleId)
    {
        if (preg_match('/^[A-Z0-9]{10}$/D', $prefix) !== 1) {
            throw new InvalidArgumentException('The App ID prefix must be 10 uppercase letters or digits.');
        }

        if (strlen($bundleId) > 255 || preg_match('/^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$/D', $bundleId) !== 1) {
            throw new InvalidArgumentException('The bundle ID must be letters, digits, and hyphens, separated by periods.');
        }
    }

    public function __toString(): string
    {
        return $this->prefix.'.'.$this->bundleId;
    }

    /** Parses `PREFIX.bundle.id`, for example `ABCDE12345.com.example.app`. */
    public static function fromString(string $appId): self
    {
        $parts = explode('.', $appId, 2);

        if (count($parts) !== 2) {
            throw new InvalidArgumentException('An App ID is the prefix, a period, and the bundle ID.');
        }

        return new self($parts[0], $parts[1]);
    }

    /** The SHA-256 of the App ID, as raw bytes: the expected RP ID hash. */
    public function hash(): string
    {
        return hash('sha256', (string) $this, true);
    }
}
