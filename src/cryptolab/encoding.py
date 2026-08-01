"""Strict text, hexadecimal, binary, and file input helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptolab.exceptions import InputError, InputValidationError

if TYPE_CHECKING:
    from pathlib import Path


BITS_PER_BYTE = 8
HEX_CHARACTERS_PER_BYTE = 2


@dataclass(frozen=True, slots=True)
class ByteInput:
    """One explicitly selected byte source."""

    label: str
    source_kind: str
    data: bytes


def validate_bit_string(value: str, *, label: str = "bit string", allow_empty: bool = False) -> str:
    """Validate a canonical binary string containing only zero and one."""

    if not value and not allow_empty:
        raise InputValidationError(f"{label.capitalize()} must not be empty.")
    invalid = next((symbol for symbol in value if symbol not in {"0", "1"}), None)
    if invalid is not None:
        raise InputValidationError(
            f"{label.capitalize()} must contain only '0' and '1'; found {invalid!r}."
        )
    return value


def parse_hex_bytes(value: str, *, label: str = "hexadecimal input") -> bytes:
    """Parse canonical hexadecimal text without prefixes, spaces, or separators."""

    if any(symbol.isspace() for symbol in value) or value.lower().startswith("0x"):
        raise InputValidationError(
            f"{label.capitalize()} must not contain whitespace, separators, or a 0x prefix."
        )
    if len(value) % HEX_CHARACTERS_PER_BYTE != 0:
        raise InputValidationError(
            f"{label.capitalize()} must contain an even number of characters."
        )
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise InputValidationError(
            f"{label.capitalize()} must contain hexadecimal characters only."
        ) from error


def bytes_to_bit_string(data: bytes) -> str:
    """Return an eight-bit binary representation for every input byte."""

    return "".join(f"{value:08b}" for value in data)


def bit_string_to_bytes(value: str, *, label: str = "bit string") -> bytes:
    """Convert a byte-aligned canonical binary string to bytes."""

    validated = validate_bit_string(value, label=label, allow_empty=True)
    if len(validated) % BITS_PER_BYTE != 0:
        raise InputValidationError(f"{label.capitalize()} length must be a multiple of 8.")
    return bytes(
        int(validated[index : index + BITS_PER_BYTE], 2)
        for index in range(0, len(validated), BITS_PER_BYTE)
    )


def read_byte_source(
    *,
    label: str,
    text: str | None,
    hex_value: str | None,
    file: Path | None,
) -> ByteInput:
    """Read exactly one explicit byte source using UTF-8, hexadecimal, or a file."""

    selected = sum(value is not None for value in (text, hex_value, file))
    if selected != 1:
        raise InputValidationError(
            f"Select exactly one source for {label}: --{label}-text, --{label}-hex, or "
            f"--{label}-file."
        )
    if text is not None:
        return ByteInput(
            label=label,
            source_kind="text",
            data=text.encode("utf-8", errors="strict"),
        )
    if hex_value is not None:
        return ByteInput(
            label=label,
            source_kind="hex",
            data=parse_hex_bytes(hex_value, label=f"{label} hexadecimal input"),
        )
    if file is None:  # pragma: no cover
        raise RuntimeError("Internal byte-source selection invariant failure.")
    try:
        return ByteInput(label=label, source_kind="file", data=file.read_bytes())
    except OSError as error:
        raise InputError(f"Unable to read {label} file: {file}") from error
