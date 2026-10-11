<?php

declare(strict_types=1);

use AppAttest\Exception\Failure;
use AppAttest\Internal\Der;

function tlv(int $tag, string $content): string
{
    $length = strlen($content);

    return chr($tag).match (true) {
        $length < 0x80 => chr($length),
        $length <= 0xFF => "\x81".chr($length),
        default => "\x82".pack('n', $length),
    }.$content;
}

/** @param list<string> $extensions DER Extension SEQUENCEs */
function certificateWith(array $extensions, ?string $wrapper = null): string
{
    $list = $wrapper ?? tlv(0xA3, tlv(0x30, implode('', $extensions)));
    $tbs = tlv(0x30, tlv(0xA0, "\x02\x01\x02")."\x02\x01\x01".tlv(0x30, '').tlv(0x30, '').tlv(0x30, '').tlv(0x30, '').tlv(0x30, '').$list);

    return tlv(0x30, $tbs.tlv(0x30, '')."\x03\x01\x00");
}

function extension(string $oid, string $value, ?bool $critical = null): string
{
    return tlv(0x30, tlv(0x06, $oid).($critical === null ? '' : tlv(0x01, $critical ? "\xFF" : "\x00")).tlv(0x04, $value));
}

it('reads short and long lengths', function (): void {
    expect(Der::element("\x04\x01A", 0, 3))->toBe(['tag' => 4, 'start' => 2, 'end' => 3])
        ->and(Der::element("\x04\x81\x80".str_repeat('A', 128), 0, 131))->toBe(['tag' => 4, 'start' => 3, 'end' => 131])
        ->and(Der::element("\x04\x82\x01\x00".str_repeat('A', 256), 0, 260))->toBe(['tag' => 4, 'start' => 4, 'end' => 260]);
});

it('refuses lengths and tags outside DER', function (string $data): void {
    expect(failureOf(fn () => Der::element($data, 0, strlen($data))))->toBe(Failure::InvalidCertificate);
})->with([
    'empty' => [''],
    'one byte' => ["\x04"],
    'indefinite' => ["\x30\x80\x00\x00"],
    'non-minimal long form' => ["\x04\x81\x05AAAAA"],
    'leading zero' => ["\x04\x82\x00\x80".str_repeat('A', 128)],
    'five length bytes' => ["\x04\x85\x00\x00\x00\x00\x01A"],
    'truncated length' => ["\x04\x82\x01"],
    'truncated content' => ["\x04\x05AAAA"],
    'multi-byte tag' => ["\x1F\x81\x01\x01A"],
]);

it('stays inside the limit', function (): void {
    expect(failureOf(fn () => Der::element("\x04\x03AAA", 0, 4)))->toBe(Failure::InvalidCertificate)
        ->and(failureOf(fn () => Der::children("\x04\x01A\x04\x01B", 0, 5)))->toBe(Failure::InvalidCertificate);
});

it('reads extensions with their critical flags', function (): void {
    $certificate = certificateWith([extension("\x55\x1D\x13", "\x30\x00", true), extension("\x2A\x03", 'value'), extension("\x2A\x04", 'x', false)]);

    expect(Der::extensions($certificate))->toBe([
        "\x55\x1D\x13" => ['critical' => true, 'value' => "\x30\x00"],
        "\x2A\x03" => ['critical' => false, 'value' => 'value'],
        "\x2A\x04" => ['critical' => false, 'value' => 'x'],
    ]);
});

it('returns no extensions for a certificate without them', function (): void {
    expect(Der::extensions(certificateWith([], '')))->toBe([]);
});

it('refuses malformed extension lists', function (string $certificate): void {
    expect(failureOf(fn () => Der::extensions($certificate)))->toBe(Failure::InvalidCertificate);
})->with([
    'duplicate OID' => [certificateWith([extension("\x2A\x03", 'a'), extension("\x2A\x03", 'b')])],
    'two extension lists' => [certificateWith([], tlv(0xA3, tlv(0x30, '')).tlv(0xA3, tlv(0x30, '')))],
    'list not a SEQUENCE' => [certificateWith([], tlv(0xA3, tlv(0x31, '')))],
    'two lists in the wrapper' => [certificateWith([], tlv(0xA3, tlv(0x30, '').tlv(0x30, '')))],
    'extension not a SEQUENCE' => [certificateWith([tlv(0x31, tlv(0x06, "\x2A\x03").tlv(0x04, 'a'))])],
    'value not an OCTET STRING' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x03, "\x00a"))])],
    'no OID' => [certificateWith([tlv(0x30, tlv(0x04, 'a'))])],
    'middle not a BOOLEAN' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x02, "\x01").tlv(0x04, 'a'))])],
    'long BOOLEAN' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x01, "\xFF\xFF").tlv(0x04, 'a'))])],
    'four fields' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x01, "\xFF").tlv(0x04, 'a').tlv(0x04, 'b'))])],
    'not a SEQUENCE' => ["\x31\x00"],
    'trailing byte' => [certificateWith([])."\x00"],
    'two parts' => [tlv(0x30, tlv(0x30, '').tlv(0x30, ''))],
    'TBS not a SEQUENCE' => [tlv(0x30, tlv(0x31, '').tlv(0x30, '')."\x03\x01\x00")],
]);

it('reads the App Attest nonce', function (): void {
    $nonce = random_bytes(32);

    expect(Der::nonce("\x30\x24\xA1\x22\x04\x20".$nonce))->toBe($nonce);
});

it('refuses a nonce extension of another shape', function (string $value): void {
    expect(failureOf(fn () => Der::nonce($value)))->toBe(Failure::InvalidCertificate);
})->with([
    'empty' => [''],
    'bare OCTET STRING' => ["\x04\x02AB"],
    'trailing byte' => ["\x30\x06\xA1\x04\x04\x02AB\x00"],
    '[0] tag' => ["\x30\x06\xA0\x04\x04\x02AB"],
    'two tagged elements' => ["\x30\x0C\xA1\x04\x04\x02AB\xA1\x04\x04\x02AB"],
    'two OCTET STRINGs' => ["\x30\x0A\xA1\x08\x04\x02AB\x04\x02AB"],
    'INTEGER inside' => ["\x30\x06\xA1\x04\x02\x02AB"],
    'empty [1]' => ["\x30\x02\xA1\x00"],
]);
