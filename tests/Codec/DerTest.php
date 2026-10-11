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

function extension(string $oid, string $value, ?bool $critical = null): string
{
    return tlv(0x30, tlv(0x06, $oid).($critical === null ? '' : tlv(0x01, $critical ? "\xFF" : "\x00")).tlv(0x04, $value));
}

/**
 * A certificate shape for the reader: the signature is not valid, and only OpenSSL checks it.
 *
 * @param  list<string>|null  $extensions  DER Extension SEQUENCEs, or null for no [3] element.
 */
function certificateWith(
    ?array $extensions = [],
    ?string $validity = null,
    ?string $afterKey = null,
    string $issuer = "\x30\x0D\x31\x0B\x30\x09\x06\x03\x55\x04\x03\x0C\x02CA",
    string $subject = "\x30\x0F\x31\x0D\x30\x0B\x06\x03\x55\x04\x03\x0C\x04leaf",
    string $version = "\xA0\x03\x02\x01\x02",
): string {
    $validity ??= tlv(0x30, tlv(0x17, '260101000000Z').tlv(0x17, '270101000000Z'));
    $afterKey ??= $extensions === null ? '' : tlv(0xA3, tlv(0x30, implode('', $extensions)));
    $tbs = tlv(0x30, $version."\x02\x01\x01".tlv(0x30, '').$issuer.$validity.$subject.tlv(0x30, '').$afterKey);

    return tlv(0x30, $tbs.tlv(0x30, '')."\x03\x01\x00");
}

it('reads short and long lengths', function (): void {
    expect(Der::element("\x04\x01A", 0, 3))->toBe(['tag' => 4, 'offset' => 0, 'start' => 2, 'end' => 3])
        ->and(Der::element("\x04\x7F".str_repeat('A', 127), 0, 129))->toBe(['tag' => 4, 'offset' => 0, 'start' => 2, 'end' => 129])
        ->and(Der::element("\x04\x84\x01\x00\x00\x00".str_repeat('A', 0x1000000), 0, 6 + 0x1000000)['end'])->toBe(6 + 0x1000000)
        ->and(Der::element("\x04\x81\x80".str_repeat('A', 128), 0, 131))->toBe(['tag' => 4, 'offset' => 0, 'start' => 3, 'end' => 131])
        ->and(Der::element("\x00\x04\x82\x01\x00".str_repeat('A', 256), 1, 261))->toBe(['tag' => 4, 'offset' => 1, 'start' => 5, 'end' => 261]);
});

it('refuses lengths and tags outside DER', function (string $data): void {
    expect(failureOf(fn () => Der::element($data, 0, strlen($data))))->toBe(Failure::InvalidCertificate);
})->with([
    'empty' => [''],
    'one byte' => ["\x04"],
    'indefinite' => ["\x30\x80\x00\x00"],
    'indefinite at the end' => ["\x30\x80"],
    'indefinite before 128 bytes' => ["\x04\x80".str_repeat('A', 128)],
    'long form for 127 bytes' => ["\x04\x81\x7F".str_repeat('A', 127)],
    'non-minimal long form' => ["\x04\x81\x05AAAAA"],
    'leading zero' => ["\x04\x82\x00\x80".str_repeat('A', 128)],
    'five length bytes' => ["\x04\x85\x01\x00\x00\x00\x00"],
    'truncated length' => ["\x04\x82\x01"],
    'truncated content' => ["\x04\x05AAAA"],
    'multi-byte tag' => ["\x1F\x01\x00"],
]);

it('stays inside the limit and the data', function (): void {
    expect(failureOf(fn () => Der::element("\x04\x03AAA", 0, 4)))->toBe(Failure::InvalidCertificate)
        ->and(failureOf(fn () => Der::element("\x04\x01A", 0, 9)))->toBe(Failure::InvalidCertificate)
        ->and(failureOf(fn () => Der::element("\x04\x01A", -1, 3)))->toBe(Failure::InvalidCertificate)
        ->and(failureOf(fn () => Der::element("\x00\x04", -1, 2)))->toBe(Failure::InvalidCertificate)
        ->and(failureOf(fn () => Der::children("\x04\x01A\x04\x01B", 0, 5)))->toBe(Failure::InvalidCertificate);
});

it('reads the names, times, and extensions of a certificate', function (): void {
    $certificate = Der::certificate(certificateWith([extension("\x55\x1D\x13", "\x30\x00", true), extension("\x2A\x03", 'value'), extension("\x2A\x04", 'x', false)]));

    expect($certificate['issuer'])->toBe("\x30\x0D\x31\x0B\x30\x09\x06\x03\x55\x04\x03\x0C\x02CA")
        ->and($certificate['subject'])->toBe("\x30\x0F\x31\x0D\x30\x0B\x06\x03\x55\x04\x03\x0C\x04leaf")
        ->and($certificate['notBefore'])->toBe(gmmktime(0, 0, 0, 1, 1, 2026))
        ->and($certificate['notAfter'])->toBe(gmmktime(0, 0, 0, 1, 1, 2027))
        ->and($certificate['extensions'])->toBe([
            ['oid' => "\x55\x1D\x13", 'critical' => true, 'value' => "\x30\x00"],
            ['oid' => "\x2A\x03", 'critical' => false, 'value' => 'value'],
            ['oid' => "\x2A\x04", 'critical' => false, 'value' => 'x'],
        ])
        ->and(Der::extensionValue($certificate['extensions'], "\x2A\x03"))->toBe('value')
        ->and(Der::extensionValue($certificate['extensions'], "\x2A\x05"))->toBeNull();
});

it('keeps an OID that looks like a number as a string', function (): void {
    $extensions = Der::certificate(certificateWith([extension('123', 'a'), extension('124', 'b')]))['extensions'];

    expect($extensions[0]['oid'])->toBe('123')
        ->and(Der::extensionValue($extensions, '124'))->toBe('b')
        ->and(failureOf(fn () => Der::certificate(certificateWith([extension('123', 'a'), extension('123', 'b')]))))->toBe(Failure::InvalidCertificate);
});

it('returns no extensions for a certificate without them', function (): void {
    expect(Der::certificate(certificateWith(null))['extensions'])->toBe([])
        ->and(Der::certificate(certificateWith(afterKey: "\x81\x02\x00\x01\x82\x02\x00\x01"))['extensions'])->toBe([]);
});

it('reads the optional fields after the key in their RFC 5280 order', function (string $afterKey, int $extensions): void {
    expect(Der::certificate(certificateWith(afterKey: $afterKey))['extensions'])->toHaveCount($extensions);
})->with([
    'issuer unique ID' => ["\x81\x02\x00\x01", 0],
    'subject unique ID' => ["\x82\x02\x00\x01", 0],
    'both unique IDs' => ["\x81\x02\x00\x01\x82\x02\x00\x01", 0],
    'issuer unique ID and extensions' => ["\x81\x02\x00\x01".tlv(0xA3, tlv(0x30, extension("\x2A\x03", 'v'))), 1],
    'subject unique ID and extensions' => ["\x82\x02\x00\x01".tlv(0xA3, tlv(0x30, extension("\x2A\x03", 'v'))), 1],
    'both unique IDs and extensions' => ["\x81\x02\x00\x01\x82\x02\x00\x01".tlv(0xA3, tlv(0x30, extension("\x2A\x03", 'v'))), 1],
]);

it('refuses malformed certificates and extension lists', function (string $certificate): void {
    expect(failureOf(fn () => Der::certificate($certificate)))->toBe(Failure::InvalidCertificate);
})->with([
    'duplicate OID' => [certificateWith([extension("\x2A\x03", 'a'), extension("\x2A\x03", 'b')])],
    'two extension lists' => [certificateWith(afterKey: tlv(0xA3, tlv(0x30, '')).tlv(0xA3, tlv(0x30, '')))],
    'extensions before a unique ID' => [certificateWith(afterKey: tlv(0xA3, tlv(0x30, ''))."\x81\x02\x00\x01")],
    'unknown field after the key' => [certificateWith(afterKey: "\x05\x00")],
    'unique IDs in the wrong order' => [certificateWith(afterKey: "\x82\x02\x00\x01\x81\x02\x00\x01")],
    'a [0] tag after the key' => [certificateWith(afterKey: "\x80\x02\x00\x01")],
    'only an OID' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03"))])],
    'algorithm not a SEQUENCE' => [tlv(0x30, tlv(0x30, "\xA0\x03\x02\x01\x02")."\x05\x00\x03\x01\x00")],
    'list not a SEQUENCE' => [certificateWith(afterKey: tlv(0xA3, tlv(0x31, '')))],
    'two lists in the wrapper' => [certificateWith(afterKey: tlv(0xA3, tlv(0x30, '').tlv(0x30, '')))],
    'extension not a SEQUENCE' => [certificateWith([tlv(0x31, tlv(0x06, "\x2A\x03").tlv(0x04, 'a'))])],
    'value not an OCTET STRING' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x03, "\x00a"))])],
    'no OID' => [certificateWith([tlv(0x30, tlv(0x04, 'a'))])],
    'middle not a BOOLEAN' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x02, "\x01").tlv(0x04, 'a'))])],
    'BOOLEAN of two bytes' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x01, "\xFF\xFF").tlv(0x04, 'a'))])],
    'BOOLEAN 0x01' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x01, "\x01").tlv(0x04, 'a'))])],
    'four fields' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x01, "\xFF").tlv(0x04, 'a').tlv(0x04, 'b'))])],
    'version 1 (no [0])' => [certificateWith(version: '')],
    'one validity time' => [certificateWith(validity: tlv(0x30, tlv(0x17, '260101000000Z')))],
    'validity not a SEQUENCE' => [certificateWith(validity: tlv(0x31, tlv(0x17, '260101000000Z').tlv(0x17, '270101000000Z')))],
    'not a SEQUENCE' => ["\x31\x00"],
    'trailing byte' => [certificateWith()."\x00"],
    'two parts' => [tlv(0x30, tlv(0x30, '').tlv(0x30, ''))],
    'signature not a BIT STRING' => [tlv(0x30, tlv(0x30, '').tlv(0x30, '')."\x04\x01\x00")],
    'TBS not a SEQUENCE' => [tlv(0x30, tlv(0x31, '').tlv(0x30, '')."\x03\x01\x00")],
    'TBS without fields' => [tlv(0x30, tlv(0x30, '').tlv(0x30, '')."\x03\x01\x00")],
]);

it('reads validity times in UTC', function (int $tag, string $time, int $expected): void {
    $certificate = certificateWith(validity: tlv(0x30, tlv($tag, $time).tlv(0x17, '491231235959Z')));

    expect(Der::certificate($certificate)['notBefore'])->toBe($expected);
})->with([
    'UTCTime' => [0x17, '260308023000Z', gmmktime(2, 30, 0, 3, 8, 2026)],
    'UTCTime 50 is 1950' => [0x17, '500101000000Z', gmmktime(0, 0, 0, 1, 1, 1950)],
    'UTCTime 49 is 2049' => [0x17, '491231235959Z', gmmktime(23, 59, 59, 12, 31, 2049)],
    'GeneralizedTime' => [0x18, '20500101000000Z', gmmktime(0, 0, 0, 1, 1, 2050)],
    'leap day' => [0x18, '20280229120000Z', gmmktime(12, 0, 0, 2, 29, 2028)],
]);

it('does not depend on the process time zone', function (): void {
    $zone = date_default_timezone_get();
    date_default_timezone_set('America/Los_Angeles');

    try {
        $time = Der::certificate(certificateWith(validity: tlv(0x30, tlv(0x17, '260308023000Z').tlv(0x17, '270101000000Z'))))['notBefore'];
    } finally {
        date_default_timezone_set($zone);
    }

    expect($time)->toBe((new \DateTimeImmutable('2026-03-08T02:30:00Z'))->getTimestamp());
});

it('refuses validity times outside RFC 5280', function (int $tag, string $time): void {
    $certificate = certificateWith(validity: tlv(0x30, tlv($tag, $time).tlv(0x17, '491231235959Z')));

    expect(failureOf(fn () => Der::certificate($certificate)))->toBe(Failure::InvalidCertificate);
})->with([
    'fractional seconds' => [0x18, '20260101000000.5Z'],
    'offset' => [0x17, '260101000000+0000'],
    'no seconds' => [0x17, '2601010000Z'],
    'no Z' => [0x17, '260101000000'],
    'lowercase z' => [0x17, '260101000000z'],
    'letters' => [0x17, 'ZZZZZZZZZZZZZ'],
    'NUL byte' => [0x17, "26010100000\0Z"],
    'trailing newline' => [0x17, "260101000000Z\n"],
    'GeneralizedTime with two-digit year' => [0x18, '260101000000Z'],
    'UTCTime with four-digit year' => [0x17, '20260101000000Z'],
    '30 February' => [0x17, '260230000000Z'],
    'month 13' => [0x17, '261301000000Z'],
    'day 0' => [0x17, '260100000000Z'],
    'hour 24' => [0x17, '260101240000Z'],
    'minute 60' => [0x17, '260101006000Z'],
    'second 60' => [0x17, '260101000060Z'],
    'year 0000' => [0x18, '00000101000000Z'],
    'not a time type' => [0x04, '260101000000Z'],
]);

it('decodes basicConstraints', function (string $value, array $expected): void {
    expect(Der::basicConstraints($value))->toBe($expected);
})->with([
    'empty: not a CA' => ["\x30\x00", ['ca' => false, 'pathLength' => null]],
    'CA' => ["\x30\x03\x01\x01\xFF", ['ca' => true, 'pathLength' => null]],
    'CA with path length 0' => ["\x30\x06\x01\x01\xFF\x02\x01\x00", ['ca' => true, 'pathLength' => 0]],
    'CA with path length 127' => ["\x30\x06\x01\x01\xFF\x02\x01\x7F", ['ca' => true, 'pathLength' => 127]],
    'CA with path length 128' => ["\x30\x07\x01\x01\xFF\x02\x02\x00\x80", ['ca' => true, 'pathLength' => 128]],
    'CA with path length 200' => ["\x30\x07\x01\x01\xFF\x02\x02\x00\xC8", ['ca' => true, 'pathLength' => 200]],
    'CA with path length 258' => ["\x30\x07\x01\x01\xFF\x02\x02\x01\x02", ['ca' => true, 'pathLength' => 258]],
    'CA with path length 32767' => ["\x30\x07\x01\x01\xFF\x02\x02\x7F\xFF", ['ca' => true, 'pathLength' => 32767]],
    'explicit false' => ["\x30\x03\x01\x01\x00", ['ca' => false, 'pathLength' => null]],
]);

it('refuses malformed basicConstraints', function (string $value): void {
    expect(failureOf(fn () => Der::basicConstraints($value)))->toBe(Failure::InvalidCertificate);
})->with([
    'the text CA:TRUE' => ['CA:TRUE'],
    'not a SEQUENCE' => ["\x31\x03\x01\x01\xFF"],
    'BOOLEAN 0x01' => ["\x30\x03\x01\x01\x01"],
    'negative path length' => ["\x30\x06\x01\x01\xFF\x02\x01\xFF"],
    'non-minimal path length' => ["\x30\x07\x01\x01\xFF\x02\x02\x00\x05"],
    'non-minimal path length 127' => ["\x30\x07\x01\x01\xFF\x02\x02\x00\x7F"],
    'negative path length 0x80' => ["\x30\x06\x01\x01\xFF\x02\x01\x80"],
    'negative two-byte path length' => ["\x30\x07\x01\x01\xFF\x02\x02\x80\x00"],
    'path length of three bytes' => ["\x30\x08\x01\x01\xFF\x02\x03\x01\x00\x00"],
    'empty path length' => ["\x30\x05\x01\x01\xFF\x02\x00"],
    'path length before the flag' => ["\x30\x06\x02\x01\x00\x01\x01\xFF"],
    'extra field' => ["\x30\x05\x01\x01\xFF\x05\x00"],
    'trailing byte' => ["\x30\x03\x01\x01\xFF\x00"],
]);

it('reads keyCertSign from keyUsage', function (string $value, bool $expected): void {
    expect(Der::allowsCertificateSigning($value))->toBe($expected);
})->with([
    'keyCertSign and cRLSign' => ["\x03\x02\x01\x06", true],
    'keyCertSign only' => ["\x03\x02\x02\x04", true],
    'digitalSignature' => ["\x03\x02\x07\x80", false],
    'encipherOnly' => ["\x03\x02\x00\x01", false],
    'cRLSign only' => ["\x03\x02\x01\x02", false],
    'every bit but keyCertSign' => ["\x03\x02\x00\xFB", false],
    'Apple credential usage' => ["\x03\x02\x04\xF0", false],
    'two bytes with decipherOnly' => ["\x03\x03\x07\x04\x80", true],
]);

it('refuses malformed keyUsage', function (string $value): void {
    expect(failureOf(fn () => Der::allowsCertificateSigning($value)))->toBe(Failure::InvalidCertificate);
})->with([
    'the text Certificate Sign' => ['Certificate Sign'],
    'no bits' => ["\x03\x01\x00"],
    'eight unused bits' => ["\x03\x02\x08\x04"],
    'OCTET STRING' => ["\x04\x02\x01\x06"],
    'trailing byte' => ["\x03\x02\x01\x06\x00"],
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
