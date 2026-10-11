<?php

declare(strict_types=1);

use AppAttest\Tests\Support\ArchitectureChecker;

/** Builds the internal namespace from parts, so that this file passes the check itself. */
function internalNamespace(string $suffix = ''): string
{
    return 'AppAttest'.'\\'.'Internal'.$suffix;
}

it('finds each way to name the internal namespace', function (string $source): void {
    expect(ArchitectureChecker::violations("<?php\n".$source))->not->toBe([]);
})->with([
    'import' => ['use '.internalNamespace('\\Cbor').';'],
    'fully qualified call' => ['\\'.internalNamespace('\\Cbor').'::decode("");'],
    'relative to the namespace' => ['namespace AppAttest; Internal\\Cbor::decode("");'],
    'namespace keyword' => ['namespace AppAttest; namespace\\Internal\\Cbor::decode("");'],
    'aliased root' => ['use AppAttest as A; A\\Internal\\Cbor::decode("");'],
    'group import' => ['use AppAttest\\{Internal\\Cbor};'],
    'type declaration' => ['function f(\\'.internalNamespace('\\CborMap').' $map): void {}'],
    'instanceof' => ['$x instanceof \\'.internalNamespace('\\ByteString').';'],
    'class string' => ['$class = "'.str_replace('\\', '\\\\', internalNamespace('\\Cbor')).'";'],
    'namespace declaration' => ['namespace '.internalNamespace().';'],
    'syntax error' => ['function ('],
    'lowercase name' => ['\\'.strtolower(internalNamespace('\\Cbor')).'::decode("");'],
    'lowercase class string' => ['$class = "'.str_replace('\\', '\\\\', strtolower(internalNamespace('\\Cbor'))).'";'],
]);

it('allows the public API and similar names', function (string $source): void {
    expect(ArchitectureChecker::violations("<?php\n".$source))->toBe([]);
})->with([
    'public classes' => ['use AppAttest\\Verifier; use AppAttest\\Exception\\Failure;'],
    'another Internal namespace' => ['use Vendor\\Internal\\Cbor;'],
    'a similar prefix' => ['use AppAttest\\InternalTools\\Thing;'],
    'a comment' => ['// '.internalNamespace('\\Cbor')],
    'a similar prefix in a string' => ['$class = "AppAttest\\\\InternalTools";'],
    'the public namespace in a string' => ['$class = "AppAttest\\\\Verifier";'],
]);

it('finds the internal namespace in documents', function (): void {
    expect(ArchitectureChecker::documentNamesInternal('See '.internalNamespace().'.'))->toBeTrue()
        ->and(ArchitectureChecker::documentNamesInternal('Internal\\Cbor'))->toBeTrue()
        ->and(ArchitectureChecker::documentNamesInternal('Use AppAttest\\Verifier.'))->toBeFalse();
});
