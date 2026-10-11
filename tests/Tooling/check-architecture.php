<?php

declare(strict_types=1);

/**
 * Keeps AppAttest\Internal internal.
 *
 * Only src/ and tests/Codec/ may name the AppAttest\Internal namespace. Other
 * tests use the public API, as consumers do. The README and CONTEXT.md must not
 * show internal classes as entry points.
 *
 * Run with composer test:architecture.
 */
const INTERNAL_NAMESPACE = 'AppAttest\\Internal';

const ALLOWED = ['src/', 'tests/Codec/'];

$root = dirname(__DIR__, 2);
$violations = [];
$checked = 0;

/** @return list<string> Paths relative to the root. */
function phpFilesIn(string $root, string $directory): array
{
    $files = [];
    $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root.'/'.$directory, \FilesystemIterator::SKIP_DOTS));

    foreach ($iterator as $file) {
        if ($file instanceof \SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
            $files[] = str_replace('\\', '/', substr($file->getPathname(), strlen($root) + 1));
        }
    }

    sort($files);

    return $files;
}

/** True when the PHP source names the internal namespace in code (not in comments or strings). */
function namesInternal(string $source): bool
{
    foreach (token_get_all($source) as $token) {
        if (! is_array($token) || ! in_array($token[0], [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)) {
            continue;
        }

        $name = ltrim($token[1], '\\');

        if ($name === INTERNAL_NAMESPACE || str_starts_with($name, INTERNAL_NAMESPACE.'\\')) {
            return true;
        }
    }

    return false;
}

foreach (['src', 'tests'] as $directory) {
    foreach (phpFilesIn($root, $directory) as $file) {
        $checked++;
        $allowed = array_filter(ALLOWED, static fn (string $prefix): bool => str_starts_with($file, $prefix)) !== [];
        $source = file_get_contents($root.'/'.$file);

        if (! $allowed && $source !== false && namesInternal($source)) {
            $violations[] = "{$file} uses ".INTERNAL_NAMESPACE.' (only '.implode(' and ', ALLOWED).' may)';
        }
    }
}

foreach (['README.md', 'CONTEXT.md'] as $document) {
    $contents = is_file($root.'/'.$document) ? file_get_contents($root.'/'.$document) : '';

    if ($contents !== false && str_contains($contents, 'Internal\\')) {
        $violations[] = "{$document} shows an internal class";
    }
}

if ($violations !== []) {
    fwrite(STDERR, "Architecture check failed:\n\n  • ".implode("\n  • ", $violations)."\n");

    exit(1);
}

echo "Architecture check passed ({$checked} files; only src/ and tests/Codec/ use ".INTERNAL_NAMESPACE.").\n";
