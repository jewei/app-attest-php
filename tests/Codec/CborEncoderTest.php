<?php

declare(strict_types=1);

use AppAttest\Internal\CborEncoder;

// Examples from RFC 8949, Appendix A, at each boundary of the argument sizes.
it('encodes integers as RFC 8949 does', function (int $value, string $hex): void {
    expect(bin2hex(CborEncoder::integer($value)))->toBe($hex);
})->with([
    [0, '00'],
    [1, '01'],
    [23, '17'],
    [24, '1818'],
    [255, '18ff'],
    [256, '190100'],
    [65535, '19ffff'],
    [65536, '1a00010000'],
    [4294967295, '1affffffff'],
    [4294967296, '1b0000000100000000'],
    [1000000000000, '1b000000e8d4a51000'],
    [-1, '20'],
    [-24, '37'],
    [-25, '3818'],
    [-100, '3863'],
    [-1000, '3903e7'],
]);

it('encodes strings, arrays, and maps as RFC 8949 does', function (): void {
    expect(bin2hex(CborEncoder::bytes('')))->toBe('40')
        ->and(bin2hex(CborEncoder::bytes("\x01\x02\x03\x04")))->toBe('4401020304')
        ->and(bin2hex(CborEncoder::text('')))->toBe('60')
        ->and(bin2hex(CborEncoder::text('IETF')))->toBe('6449455446')
        ->and(bin2hex(CborEncoder::text(str_repeat('a', 24))))->toBe('7818'.str_repeat('61', 24))
        ->and(bin2hex(CborEncoder::array([])))->toBe('80')
        ->and(bin2hex(CborEncoder::array([CborEncoder::integer(1), CborEncoder::integer(2), CborEncoder::integer(3)])))->toBe('83010203')
        ->and(bin2hex(CborEncoder::map([])))->toBe('a0')
        ->and(bin2hex(CborEncoder::map([1 => 2, 3 => 4])))->toBe('a201020304')
        ->and(bin2hex(CborEncoder::map(['a' => CborEncoder::integer(1), 'b' => CborEncoder::array([CborEncoder::integer(2), CborEncoder::integer(3)])])))->toBe('a26161016162820203')
        ->and(bin2hex(CborEncoder::map([-1 => -7])))->toBe('a12026');
});
