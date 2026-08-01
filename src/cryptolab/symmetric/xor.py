"""Transparent educational XOR operations over bits and bytes."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.encoding import bytes_to_bit_string, validate_bit_string
from cryptolab.exceptions import InputValidationError


@dataclass(frozen=True, slots=True)
class XORTruthRow:
    """One row of the XOR truth table."""

    left: int
    right: int
    result: int


@dataclass(frozen=True, slots=True)
class BitXORStep:
    """One bitwise XOR position."""

    position: int
    left: int
    right: int
    result: int


@dataclass(frozen=True, slots=True)
class BitXORResult:
    """Bit-string XOR result."""

    left: str
    right: str
    output: str
    steps: tuple[BitXORStep, ...]


@dataclass(frozen=True, slots=True)
class ByteXORStep:
    """One bytewise XOR position."""

    position: int
    left: int
    right: int
    result: int


@dataclass(frozen=True, slots=True)
class ByteXORResult:
    """Byte-string XOR result with canonical hexadecimal and binary forms."""

    left_hex: str
    right_hex: str
    output_hex: str
    left_bits: str
    right_bits: str
    output_bits: str
    length_bytes: int
    steps: tuple[ByteXORStep, ...]


def xor_truth_table() -> tuple[XORTruthRow, ...]:
    """Return the canonical XOR truth table."""

    return tuple(XORTruthRow(left, right, left ^ right) for left in (0, 1) for right in (0, 1))


def xor_bits(left: str, right: str) -> BitXORResult:
    """XOR two equal-length canonical bit strings."""

    validated_left = validate_bit_string(left, label="left bit string")
    validated_right = validate_bit_string(right, label="right bit string")
    if len(validated_left) != len(validated_right):
        raise InputValidationError("Bit strings must have equal length.")

    steps = tuple(
        BitXORStep(position, int(left_bit), int(right_bit), int(left_bit) ^ int(right_bit))
        for position, (left_bit, right_bit) in enumerate(
            zip(validated_left, validated_right, strict=True)
        )
    )
    return BitXORResult(
        left=validated_left,
        right=validated_right,
        output="".join(str(step.result) for step in steps),
        steps=steps,
    )


def xor_bytes(left: bytes, right: bytes) -> ByteXORResult:
    """XOR two equal-length byte strings."""

    if len(left) != len(right):
        raise InputValidationError("Byte strings must have equal length.")
    output = bytes(
        left_value ^ right_value for left_value, right_value in zip(left, right, strict=True)
    )
    steps = tuple(
        ByteXORStep(position, left_value, right_value, result_value)
        for position, (left_value, right_value, result_value) in enumerate(
            zip(left, right, output, strict=True)
        )
    )
    return ByteXORResult(
        left_hex=left.hex(),
        right_hex=right.hex(),
        output_hex=output.hex(),
        left_bits=bytes_to_bit_string(left),
        right_bits=bytes_to_bit_string(right),
        output_bits=bytes_to_bit_string(output),
        length_bytes=len(left),
        steps=steps,
    )
