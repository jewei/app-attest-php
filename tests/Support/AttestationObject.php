<?php

declare(strict_types=1);

namespace AppAttest\Tests\Support;

use RuntimeException;

/** The fields of a test attestation object before CBOR encoding. Tests change them to break one check. */
final class AttestationObject
{
    /** @var array<string, mixed> Fields to add to the object. */
    public array $extraFields = [];

    /** @var array<string, mixed> Fields to add to the statement. */
    public array $extraStatementFields = [];

    /** @var list<string> Fields to remove from the object and the statement. */
    public array $omit = [];

    /** Replaces the statement map when it is not null. */
    public mixed $statement = null;

    private bool $replaced = false;

    private mixed $replacement = null;

    /** @param list<mixed> $x5c */
    public function __construct(
        public mixed $format,
        public array $x5c,
        public mixed $receipt,
        public mixed $authData,
    ) {}

    /** Encodes $value instead of the object. */
    public function replaceWith(mixed $value): void
    {
        $this->replaced = true;
        $this->replacement = $value;
    }

    public function authDataBytes(): string
    {
        return self::bytes($this->authData);
    }

    public function certificate(int $index): string
    {
        return self::bytes($this->x5c[$index] ?? null);
    }

    public function encode(): string
    {
        if ($this->replaced) {
            return CborEncoder::encode($this->replacement);
        }

        $statement = $this->statement ?? array_diff_key(
            ['x5c' => $this->x5c, 'receipt' => $this->receipt] + $this->extraStatementFields,
            array_flip($this->omit),
        );
        $object = ['fmt' => $this->format, 'attStmt' => $statement, 'authData' => $this->authData] + $this->extraFields;

        return CborEncoder::encode(array_diff_key($object, array_flip($this->omit)));
    }

    private static function bytes(mixed $value): string
    {
        if (! $value instanceof Bytes) {
            throw new RuntimeException('The field is not a byte string.');
        }

        return $value->value;
    }
}
