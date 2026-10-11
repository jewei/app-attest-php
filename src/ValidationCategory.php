<?php

declare(strict_types=1);

namespace AppAttest;

/**
 * How the app was launched and distributed, from `apple_validation_category_01`.
 *
 * Apple defines 0 as invalid, and 7, 8, and 9 as categories that are not
 * appropriate for an app. They have no case, so the verifier refuses them,
 * and any value that Apple adds later, until this enum names it.
 */
enum ValidationCategory: int
{
    case OperatingSystem = 1;
    case TestFlight = 2;
    case Development = 3;
    case AppStore = 4;
    case EnterpriseOrAdHoc = 5;
    case DeveloperId = 6;
    case Other = 10;
}
