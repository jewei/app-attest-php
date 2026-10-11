<?php

declare(strict_types=1);

namespace AppAttest;

/**
 * Which validation categories (apple_validation_category_01) the verifier accepts.
 *
 * Devices on older iOS versions may write no category. only() refuses them; onlyOrMissing() accepts them.
 * Every policy refuses 0 (invalid), 7 to 9 (not appropriate for apps), and values that ValidationCategory does
 * not name yet.
 */
final readonly class CategoryPolicy
{
    /** @param list<ValidationCategory>|null $categories Null: every named category. */
    private function __construct(private ?array $categories, private bool $allowsMissing) {}

    /** Only these categories; a missing category fails. */
    public static function only(ValidationCategory $category, ValidationCategory ...$more): self
    {
        return new self([$category, ...array_values($more)], false);
    }

    /** These categories, or no category (devices that do not write one). */
    public static function onlyOrMissing(ValidationCategory $category, ValidationCategory ...$more): self
    {
        return new self([$category, ...array_values($more)], true);
    }

    /**
     * Every category that ValidationCategory names, including Development and DeveloperId, and a missing one.
     * A package upgrade that names a new category widens this policy.
     */
    public static function any(): self
    {
        return new self(null, true);
    }

    public function allows(?ValidationCategory $category): bool
    {
        if ($category === null) {
            return $this->allowsMissing;
        }

        return $this->categories === null || in_array($category, $this->categories, true);
    }

}
