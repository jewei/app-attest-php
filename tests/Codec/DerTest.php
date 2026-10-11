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
    ?array $extensions = null,
    ?string $validity = null,
    ?string $afterKey = null,
    string $issuer = "\x30\x0D\x31\x0B\x30\x09\x06\x03\x55\x04\x03\x0C\x02CA",
    string $subject = "\x30\x0F\x31\x0D\x30\x0B\x06\x03\x55\x04\x03\x0C\x04leaf",
    string $version = "\xA0\x03\x02\x01\x02",
    ?string $publicKey = null,
    ?string $signatureAlgorithm = null,
    ?string $signature = null,
): string {
    $validity ??= tlv(0x30, tlv(0x17, '260101000000Z').tlv(0x17, '270101000000Z'));
    $afterKey ??= $extensions === null ? '' : tlv(0xA3, tlv(0x30, implode('', $extensions)));
    $publicKey ??= ecKey(Der::P256);
    $tbs = tlv(0x30, $version."\x02\x01\x01".tlv(0x30, '').$issuer.$validity.$subject.$publicKey.$afterKey);

    return tlv(0x30, $tbs.($signatureAlgorithm ?? tlv(0x30, '')).($signature ?? "\x03\x01\x00"));
}

/** A SubjectPublicKeyInfo shape: id-ecPublicKey with a named curve and a placeholder point. */
function ecKey(string $curve, string $algorithm = Der::EC_PUBLIC_KEY): string
{
    return tlv(0x30, tlv(0x30, tlv(0x06, $algorithm).tlv(0x06, $curve)).tlv(0x03, "\x00\x04".str_repeat("\x01", 64)));
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
    'a 9-byte length that wraps to 133' => ["\x04\x89\x01".str_repeat("\x00", 7)."\x85".str_repeat('A', 133)],
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
    $certificate = Der::certificate(certificateWith([extension("\x55\x1D\x13", "\x30\x00", true), extension("\x2A\x03", 'value'), extension("\x2A\x04", 'x')]));

    expect($certificate['issuer'])->toBe("\x30\x0D\x31\x0B\x30\x09\x06\x03\x55\x04\x03\x0C\x02CA")
        ->and($certificate['subject'])->toBe("\x30\x0F\x31\x0D\x30\x0B\x06\x03\x55\x04\x03\x0C\x04leaf")
        ->and($certificate['notBefore'])->toBe(gmmktime(0, 0, 0, 1, 1, 2026))
        ->and($certificate['notAfter'])->toBe(gmmktime(0, 0, 0, 1, 1, 2027))
        ->and($certificate['publicKey'])->toBe(ecKey(Der::P256))
        ->and($certificate['curve'])->toBe(Der::P256)
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
    'two lists in the wrapper' => [certificateWith(afterKey: tlv(0xA3, tlv(0x30, extension("\x2A\x03", 'a')).tlv(0x30, extension("\x2A\x04", 'b'))))],
    'extension not a SEQUENCE' => [certificateWith([tlv(0x31, tlv(0x06, "\x2A\x03").tlv(0x04, 'a'))])],
    'value not an OCTET STRING' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x03, "\x00a"))])],
    'no OID' => [certificateWith([tlv(0x30, tlv(0x04, 'a'))])],
    'middle not a BOOLEAN' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x02, "\x01").tlv(0x04, 'a'))])],
    'BOOLEAN of two bytes' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x01, "\xFF\xFF").tlv(0x04, 'a'))])],
    'BOOLEAN 0x01' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x01, "\x01").tlv(0x04, 'a'))])],
    'critical written as the default FALSE' => [certificateWith([extension("\x2A\x03", 'a', false)])],
    'an INTEGER where the flag goes' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x02, "\xFF").tlv(0x04, 'a'))])],
    'an INTEGER where the OID goes' => [certificateWith([tlv(0x30, tlv(0x02, "\x01").tlv(0x04, 'a'))])],
    'an empty extension list' => [certificateWith([])],
    'version 1 written out' => [certificateWith(version: "\xA0\x03\x02\x01\x00")],
    'version 6' => [certificateWith(version: "\xA0\x03\x02\x01\x05")],
    'version as an OCTET STRING' => [certificateWith(version: "\xA0\x03\x04\x01\x02")],
    'three validity times' => [certificateWith(validity: tlv(0x30, tlv(0x17, '260101000000Z').tlv(0x17, '270101000000Z').tlv(0x17, '280101000000Z')))],
    'four top-level parts' => [(static function (): string {
        $certificate = certificateWith();
        $outer = Der::element($certificate, 0, strlen($certificate));

        return tlv(0x30, substr($certificate, $outer['start'])."\x05\x00");
    })()],
    'signature as an OCTET STRING' => [certificateWith(signature: "\x04\x01\x00")],
    'outer algorithm differs from the signed one' => [certificateWith(signatureAlgorithm: tlv(0x30, tlv(0x06, "\x2A\x86\x48\xCE\x3D\x04\x03\x02")))],
    'algorithm as a SET' => [certificateWith(signatureAlgorithm: tlv(0x31, ''))],
    'public key without a BIT STRING' => [certificateWith(publicKey: tlv(0x30, tlv(0x30, tlv(0x06, Der::EC_PUBLIC_KEY).tlv(0x06, Der::P256))))],
    'four fields' => [certificateWith([tlv(0x30, tlv(0x06, "\x2A\x03").tlv(0x01, "\xFF").tlv(0x04, 'a').tlv(0x04, 'b'))])],
    'version 1 (no [0])' => [certificateWith(version: '')],
    'one validity time' => [certificateWith(validity: tlv(0x30, tlv(0x17, '260101000000Z')))],
    'a 9-byte length' => ["\x30\x89\x01\x00\x00\x00\x00\x00\x00\x00\x85".str_repeat("\x00", 133)],
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
    'leap day' => [0x17, '280229120000Z', gmmktime(12, 0, 0, 2, 29, 2028)],
    'GeneralizedTime in 2050' => [0x18, '20500101000000Z', gmmktime(0, 0, 0, 1, 1, 2050)],
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
    'GeneralizedTime in year 50' => [0x18, '00500101000000Z'],
    'GeneralizedTime in 2049' => [0x18, '20491231235959Z'],
    'GeneralizedTime in 1999' => [0x18, '19990101000000Z'],
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
]);

it('refuses malformed basicConstraints', function (string $value): void {
    expect(failureOf(fn () => Der::basicConstraints($value)))->toBe(Failure::InvalidCertificate);
})->with([
    'the text CA:TRUE' => ['CA:TRUE'],
    'not a SEQUENCE' => ["\x31\x03\x01\x01\xFF"],
    'BOOLEAN 0x01' => ["\x30\x03\x01\x01\x01"],
    'cA written as the default FALSE' => ["\x30\x03\x01\x01\x00"],
    'a path length that looks like a flag' => ["\x30\x03\x02\x01\xFF"],
    'negative path length' => ["\x30\x06\x01\x01\xFF\x02\x01\xFF"],
    'non-minimal path length' => ["\x30\x07\x01\x01\xFF\x02\x02\x00\x05"],
    'non-minimal path length 127' => ["\x30\x07\x01\x01\xFF\x02\x02\x00\x7F"],
    'negative path length 0x80' => ["\x30\x06\x01\x01\xFF\x02\x01\x80"],
    'negative two-byte path length' => ["\x30\x07\x01\x01\xFF\x02\x02\x80\x00"],
    'path length of three bytes' => ["\x30\x08\x01\x01\xFF\x02\x03\x01\x00\x00"],
    'empty path length' => ["\x30\x05\x01\x01\xFF\x02\x00"],
    'path length before the flag' => ["\x30\x06\x02\x01\x01\x01\x01\xFF"],
    'the flag as an OCTET STRING' => ["\x30\x03\x04\x01\xFF"],
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
    'an empty BIT STRING' => ["\x03\x00"],
    'eight unused bits' => ["\x03\x02\x08\x04"],
    'keyCertSign in the unused bits' => ["\x03\x02\x03\x04"],
    'keyCertSign under five unused bits' => ["\x03\x02\x05\x04"],
    'a set bit in the unused bits' => ["\x03\x02\x01\x05"],
    'a set unused bit in the last of two bytes' => ["\x03\x03\x07\x04\x81"],
    'a trailing zero named bit' => ["\x03\x02\x00\x06"],
    'a trailing zero byte' => ["\x03\x03\x01\x06\x00"],
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

it('reads the curve of an EC key and nothing for another key', function (): void {
    expect(Der::certificate(certificateWith(publicKey: ecKey(Der::P384)))['curve'])->toBe(Der::P384)
        ->and(Der::certificate(certificateWith(publicKey: ecKey("\x05\x00", "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01")))['curve'])->toBeNull()
        ->and(Der::certificate(certificateWith(publicKey: tlv(0x30, tlv(0x30, tlv(0x06, Der::EC_PUBLIC_KEY).tlv(0x30, '')).tlv(0x03, "\x00\x04"))))['curve'])->toBeNull();
});

it('reads the platform from the App Attest platform extension', function (string $value, ?string $platform): void {
    expect(Der::platform((string) hex2bin($value)))->toBe($platform);
})->with([
    'Apple\'s sample' => ['3081cfbf8a7806040432372e30bf885003020102bf8a79090407312e302e323136bf8a7b09040732344133323562bf8a7c06040432372e30bf8a7d06040432372e30bf8a7e03020100bf8a7f03020100bf8b0003020100bf8b0103020100bf8b0203020100bf8b0303020100bf8b0403020101bf8b0503020100bf8b0a10040e32342e312e3332352e302e322c30bf8b0b10040e32342e312e3332352e302e322c30bf8b0c10040e32342e312e3332352e302e322c30bf88020a04086970686f6e656f73bf88050a0408496e7465726e616c', 'iphoneos'],
    'macOS' => ['300cbf88020804066d61636f7378', 'macosx'],
    'no platform field' => ['300abf8a7806040432372e30', null],
    'empty' => ['3000', null],
    'with a low-tag field' => ['3013a403020100bf88020a04086970686f6e656f73', 'iphoneos'],
    'with a primitive field' => ['3011850100bf88020a04086970686f6e656f73', 'iphoneos'],
]);

it('refuses a platform extension of another shape', function (string $value): void {
    expect(failureOf(fn () => Der::platform((string) hex2bin($value))))->toBe(Failure::InvalidCertificate);
})->with([
    'not a SEQUENCE' => ['310cbf88020804066d61636f7378'],
    'a non-minimal tag number' => ['300dbf8088020804066d61636f7378'],
    'a small tag number in the long form' => ['3013bf05020400bf88020a04086970686f6e656f73'],
    'a universal field' => ['30050403020100'],
    'the platform field as a primitive' => ['300c9f88020804066d61636f7378'],
    'a five-byte tag number' => ['3007bf818181810200'],
    'a truncated tag number' => ['3002bf88'],
    'a truncated length' => ['3003bf8802'],
    'the platform twice' => ['3018bf88020804066d61636f7378bf88020804066d61636f7378'],
    'the platform not an OCTET STRING' => ['300cbf88020802066d61636f7378'],
    'trailing bytes in the platform' => ['300ebf88020a04066d61636f73780000'],
]);

it('reads tag numbers from 31 in the long form, up to four bytes', function (string $value, ?string $platform): void {
    expect(Der::platform((string) hex2bin($value)))->toBe($platform);
})->with([
    'number 31' => ['3012bf1f0102bf88020a04086970686f6e656f73', 'iphoneos'],
    'a four-byte number' => ['3016bf81818101020400bf88020a04086970686f6e656f73', 'iphoneos'],
    'number 1026 as 2 bytes' => ['300ebf88020a04086970686f6e656f73', 'iphoneos'],
    'number 127 in one byte' => ['3012bf7f0102bf88020a04086970686f6e656f73', 'iphoneos'],
    'a continuation byte 0x80' => ['3014bf8180000102bf88020a04086970686f6e656f73', 'iphoneos'],
]);

it('refuses a long-form tag number below 31', function (): void {
    expect(failureOf(fn () => Der::platform((string) hex2bin('3012bf1e0102bf88020a04086970686f6e656f73'))))->toBe(Failure::InvalidCertificate);
});

it('refuses a public key algorithm that is not an OID and a named curve', function (string $algorithm): void {
    expect(Der::certificate(certificateWith(publicKey: tlv(0x30, tlv(0x30, $algorithm).tlv(0x03, "\x00\x04"))))['curve'])->toBeNull();
})->with([
    'only the algorithm' => [tlv(0x06, Der::EC_PUBLIC_KEY)],
    'curve as a SEQUENCE' => [tlv(0x06, Der::EC_PUBLIC_KEY).tlv(0x30, '')],
    'algorithm as a NULL' => [tlv(0x05, '').tlv(0x06, Der::P256)],
    'three parts' => [tlv(0x06, Der::EC_PUBLIC_KEY).tlv(0x06, Der::P256).tlv(0x05, '')],
]);

it('refuses a TBSCertificate or a signature algorithm that is not a SEQUENCE', function (int $part): void {
    $certificate = certificateWith();
    $outer = Der::element($certificate, 0, strlen($certificate));
    $offset = $outer['start'];

    for ($index = 0; $index < $part; $index++) {
        $offset = Der::element($certificate, $offset, $outer['end'])['end'];
    }

    $certificate[$offset] = "\x31";

    expect(failureOf(fn () => Der::certificate($certificate)))->toBe(Failure::InvalidCertificate);
})->with(['TBSCertificate' => [0], 'signature algorithm' => [1]]);

it('reads no curve when the key algorithm is not an OBJECT IDENTIFIER', function (): void {
    $publicKey = tlv(0x30, tlv(0x30, tlv(0x04, Der::EC_PUBLIC_KEY).tlv(0x06, Der::P256)).tlv(0x03, "\x00\x04".str_repeat("\x01", 64)));

    expect(Der::certificate(certificateWith(publicKey: $publicKey))['curve'])->toBeNull()
        ->and(Der::certificate(certificateWith())['curve'])->toBe(Der::P256);
});
