<?php

declare(strict_types=1);

/**
 * Keeps AppAttest\Internal internal.
 *
 * Only src/ and tests/Codec/ may use the internal namespace. Other tests use the
 * public API, as consumers do. The README and CONTEXT.md must not name it.
 * Every PHP file in src/, tests/, and the repository root is checked, whatever
 * its extension.
 *
 * Run with composer test:architecture.
 */

use AppAttest\Tests\Support\ArchitectureChecker;

require dirname(__DIR__, 2).'/vendor/autoload.php';

const ALLOWED = ['src/', 'tests/Codec/'];

$root = dirname(__DIR__, 2);
$violations = [];
$files = [];

foreach (['src', 'tests'] as $directory) {
    foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root.'/'.$directory, \FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file instanceof \SplFileInfo && $file->isFile()) {
            $files[] = substr($file->getPathname(), strlen($root) + 1);
        }
    }
}

foreach (glob($root.'/*.php') ?: [] as $file) {
    $files[] = basename($file);
}

sort($files);
$checked = 0;

foreach ($files as $file) {
    $source = (string) file_get_contents($root.'/'.$file);

    if (! str_contains($source, '<?php')) {
        continue;
    }

    $checked++;

    if (array_filter(ALLOWED, static fn (string $prefix): bool => str_starts_with($file, $prefix)) !== []) {
        continue;
    }

    foreach (ArchitectureChecker::violations($source) as $violation) {
        $violations[] = "{$file} {$violation}";
    }
}

foreach (['README.md', 'CONTEXT.md'] as $document) {
    if (is_file($root.'/'.$document) && ArchitectureChecker::documentNamesInternal((string) file_get_contents($root.'/'.$document))) {
        $violations[] = "{$document} names the internal namespace";
    }
}

if ($violations !== []) {
    fwrite(STDERR, "Architecture check failed. Only src/ and tests/Codec/ may use the internal namespace:\n\n  • ".implode("\n  • ", $violations)."\n");

    exit(1);
}

echo "Architecture check passed ({$checked} PHP files).\n";
