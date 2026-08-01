from __future__ import annotations

from pathlib import Path

import pytest

from cryptolab.encoding import (
    bit_string_to_bytes,
    bytes_to_bit_string,
    parse_hex_bytes,
    read_byte_source,
    validate_bit_string,
)
from cryptolab.exceptions import InputError, InputValidationError


def test_binary_and_hex_conversions() -> None:
    assert validate_bit_string("1010") == "1010"
    assert bit_string_to_bytes("01000001") == b"A"
    assert bytes_to_bit_string(b"A") == "01000001"
    assert parse_hex_bytes("Beca") == bytes.fromhex("beca")


def test_invalid_binary_and_hex_inputs() -> None:
    with pytest.raises(InputValidationError, match="only '0' and '1'"):
        validate_bit_string("102")
    with pytest.raises(InputValidationError, match="multiple of 8"):
        bit_string_to_bytes("101")
    with pytest.raises(InputValidationError, match="even number"):
        parse_hex_bytes("abc")
    with pytest.raises(InputValidationError, match="must not contain whitespace"):
        parse_hex_bytes("be ca")


def test_explicit_byte_sources(tmp_path: Path) -> None:
    source_file = tmp_path / "source.bin"
    source_file.write_bytes(b"AB")
    assert read_byte_source(label="left", text="AB", hex_value=None, file=None).data == b"AB"
    assert read_byte_source(label="left", text=None, hex_value="4142", file=None).data == b"AB"
    assert read_byte_source(label="left", text=None, hex_value=None, file=source_file).data == b"AB"

    with pytest.raises(InputValidationError, match="exactly one source"):
        read_byte_source(label="left", text=None, hex_value=None, file=None)
    with pytest.raises(InputValidationError, match="exactly one source"):
        read_byte_source(label="left", text="AB", hex_value="4142", file=None)
    with pytest.raises(InputError, match="Unable to read"):
        read_byte_source(label="left", text=None, hex_value=None, file=tmp_path / "missing")
