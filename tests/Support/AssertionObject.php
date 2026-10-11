<?php

declare(strict_types=1);

namespace AppAttest\Tests\Support;

use RuntimeException;

/** The fields of a test assertion object before CBOR encoding. Tests change them to break one check. */
final class AssertionObject
{
    /** @var array<string, mixed> Fields to add to the object. */
    public array $extraFields = [];

    /** @var list<string> Fields to remove from the object. */
    public array $omit = [];

    private bool $replaced = false;

    private mixed $replacement = null;

    public function __construct(public mixed $signature, public mixed $authenticatorData) {}

    /** Encodes $value instead of the object. */
    public function replaceWith(mixed $value): void
    {
        $this->replaced = true;
        $this->replacement = $value;
    }

    public function authenticatorDataBytes(): string
    {
        if (! $this->authenticatorData instanceof Bytes) {
            throw new RuntimeException('authenticatorData is not a byte string.');
        }

        return $this->authenticatorData->value;
    }

    public function encode(): string
    {
        if ($this->replaced) {
            return CborEncoder::encode($this->replacement);
        }

        $object = ['signature' => $this->signature, 'authenticatorData' => $this->authenticatorData] + $this->extraFields;

        return CborEncoder::encode(array_diff_key($object, array_flip($this->omit)));
    }
}
