<?php

declare(strict_types=1);

namespace AppAttest;

/**
 * The App Attest environment of a key. The app's entitlement
 * `com.apple.developer.devicecheck.appattest-environment` selects it.
 */
enum Environment: string
{
    case Production = 'production';
    case Development = 'development';

    /** The AAGUID that App Attest writes in the authenticator data of a key in this environment. */
    public function aaguid(): string
    {
        return match ($this) {
            self::Production => "appattest\0\0\0\0\0\0\0",
            self::Development => 'appattestdevelop',
        };
    }
}
