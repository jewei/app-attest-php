<?php

declare(strict_types=1);

use AppAttest\Exception\Failure;
use AppAttest\Internal\ByteString;
use AppAttest\Internal\Cbor;
use AppAttest\Tests\Support\Bytes;
use AppAttest\Tests\Support\CborEncoder;

it('decodes integers at each length boundary', function (int $value): void {
    expect(Cbor::decode(CborEncoder::encode($value)))->toBe($value);
})->with([0, 1, 23, 24, 255, 256, 65535, 65536, 0xFFFFFFFF, 0x100000000, PHP_INT_MAX, -1, -24, -25, -256, -257, -65537, PHP_INT_MIN]);

it('decodes RFC 8949 appendix A examples', function (string $hex, mixed $expected): void {
    $value = Cbor::decode((string) hex2bin($hex));

    expect($value instanceof ByteString ? ['bytes' => $value->value] : $value)->toBe($expected);
})->with([
    ['00', 0],
    ['17', 23],
    ['1818', 24],
    ['1903e8', 1000],
    ['1a000f4240', 1000000],
    ['1b000000e8d4a51000', 1000000000000],
    ['20', -1],
    ['3863', -100],
    ['3903e7', -1000],
    ['40', ['bytes' => '']],
    ['4401020304', ['bytes' => "\x01\x02\x03\x04"]],
    ['60', ''],
    ['6161', 'a'],
    ['6449455446', 'IETF'],
    ['62225c', '"\\'],
    ['62c3bc', "\u{00fc}"],
    ['63e6b0b4', "\u{6c34}"],
    ['64f0908591', "\u{10151}"],
    ['80', []],
    ['83010203', [1, 2, 3]],
    ['8301820203820405', [1, [2, 3], [4, 5]]],
    ['a201020304', [1 => 2, 3 => 4]],
    ['a26161016162820203', ['a' => 1, 'b' => [2, 3]]],
    ['826161a161626163', ['a', ['b' => 'c']]],
]);

it('refuses CBOR outside the subset', function (string $hex): void {
    expect(failureOf(fn () => Cbor::decode((string) hex2bin($hex))))->toBe(Failure::MalformedInput);
})->with([
    'empty' => [''],
    'unsigned above PHP_INT_MAX' => ['1b8000000000000000'],
    'negative below PHP_INT_MIN' => ['3b8000000000000000'],
    'reserved 28' => ['1c'],
    'reserved 29' => ['1d'],
    'reserved 30' => ['1e'],
    'indefinite byte string' => ['5f42010243030405ff'],
    'indefinite text string' => ['7f657374726561646d696e67ff'],
    'indefinite array' => ['9f018202039f0405ffff'],
    'indefinite map' => ['bf61610161629f0203ffff'],
    'tag' => ['c074323031332d30332d32315432303a30343a30305a'],
    'float' => ['f93c00'],
    'false' => ['f4'],
    'true' => ['f5'],
    'null' => ['f6'],
    'break' => ['ff'],
    'invalid UTF-8' => ['62c328'],
    'overlong UTF-8' => ['62c0af'],
    'UTF-16 surrogate' => ['63eda080'],
    'trailing byte' => ['0000'],
    'truncated argument' => ['19ff'],
    'truncated byte string' => ['44010203'],
    'huge byte string length' => ['5b7fffffffffffffff'],
    'huge array length' => ['9b7fffffffffffffff'],
    'array longer than the data' => ['8301'],
    'map key is a byte string' => ['a1410101'],
    'map key is an array' => ['a1800101'],
    'map key is a map' => ['a1a00101'],
    'duplicate map key' => ['a2616101616102'],
    'text key "1" and integer key 1' => ['a2016161613101'],
    'map missing a value' => ['a101'],
]);

it('limits nesting depth', function (): void {
    expect(Cbor::decode(str_repeat("\x81", Cbor::MAX_DEPTH - 1)."\x00"))->toBeArray()
        ->and(failureOf(fn () => Cbor::decode(str_repeat("\x81", Cbor::MAX_DEPTH)."\x00")))->toBe(Failure::MalformedInput);
});

it('limits container sizes', function (): void {
    $array = array_fill(0, Cbor::MAX_ITEMS, 0);
    $map = array_fill_keys(range(1, Cbor::MAX_ITEMS), 0);

    expect(Cbor::decode(CborEncoder::encode($array)))->toBe($array)
        ->and(Cbor::decode(CborEncoder::encode($map)))->toBe($map)
        ->and(failureOf(fn () => Cbor::decode(CborEncoder::encode([...$array, 0]))))->toBe(Failure::MalformedInput)
        ->and(failureOf(fn () => Cbor::decode(CborEncoder::encode($map + [0 => 0]))))->toBe(Failure::MalformedInput);
});

it('decodes byte strings as ByteString and text as strings', function (): void {
    $value = Cbor::decode(CborEncoder::encode(['b' => new Bytes("\xFF\x00"), 't' => 'text']));
    $bytes = is_array($value) ? ($value['b'] ?? null) : null;

    expect($bytes)->toBeInstanceOf(ByteString::class)
        ->and($bytes instanceof ByteString ? $bytes->value : null)->toBe("\xFF\x00")
        ->and(is_array($value) ? ($value['t'] ?? null) : null)->toBe('text');
});

it('decodes a prefix and returns the next offset', function (): void {
    $data = "\x05".CborEncoder::encode([1 => 2]).'rest';

    expect(Cbor::decodePrefix($data, 1))->toBe([[1 => 2], 4])
        ->and(failureOf(fn () => Cbor::decodePrefix($data, strlen($data))))->toBe(Failure::MalformedInput)
        ->and(failureOf(fn () => Cbor::decodePrefix($data, strlen($data) + 1)))->toBe(Failure::MalformedInput)
        ->and(failureOf(fn () => Cbor::decodePrefix($data, -1)))->toBe(Failure::MalformedInput);
});

it('refuses every truncation of a nested value', function (): void {
    $data = CborEncoder::encode(['a' => [1, new Bytes('xyz'), ['k' => -500]], 'b' => 'text', 7 => 65536]);

    for ($length = 0; $length < strlen($data); $length++) {
        expect(failureOf(fn () => Cbor::decode(substr($data, 0, $length))))->toBe(Failure::MalformedInput);
    }
});
