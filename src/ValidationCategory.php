<?php

declare(strict_types=1);

namespace AppAttest;

/**
 * How the app's code is signed, from `apple_validation_category_01`. The names and texts follow Apple's App Attest
 * server validation page.
 *
 * Apple defines 0 as invalid, and 7, 8, and 9 as "categories of binaries that the system generates in certain
 * restricted situations", which are not appropriate. They have no case, so the verifier refuses them, and any value
 * that Apple adds later, until this enum names it.
 *
 * A third-party app distributed by Apple reports AppStore or TestFlight; a build from Xcode reports Development.
 * OperatingSystem and Other point to code that Apple did not sign for distribution to you, for example a re-signed
 * or sideloaded app: accept them only on purpose.
 */
enum ValidationCategory: int
{
    /** An operating system executable (Apple's code-signing name: platform). Not expected from a third-party app. */
    case OperatingSystem = 1;

    /** An executable distributed through TestFlight. */
    case TestFlight = 2;

    /** An executable signed by a development code signing identity. */
    case Development = 3;

    /** An executable distributed through the App Store. */
    case AppStore = 4;

    /** An executable distributed with an Enterprise or ad hoc provisioning profile. */
    case EnterpriseOrAdHoc = 5;

    /** An executable signed using Developer ID. */
    case DeveloperId = 6;

    /**
     * An executable signed with a code signing identity that does not match any other category (Apple's code-signing
     * name: none, for ad hoc signatures and unrecognized certificate chains). Not expected from an app that Apple
     * distributed.
     */
    case Other = 10;
}
