from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from cryptolab.public_key.rsa_educational import (
    build_educational_rsa_key,
    bytes_to_integer,
    integer_to_bytes,
    textbook_rsa_decrypt,
    textbook_rsa_encrypt,
)


@given(message=st.integers(min_value=0, max_value=3232))
def test_textbook_rsa_round_trip_property(message: int) -> None:
    key = build_educational_rsa_key(61, 53, 17)
    encrypted = textbook_rsa_encrypt(message, key)
    assert textbook_rsa_decrypt(encrypted.output_value, key).plaintext == message


@given(value=st.integers(min_value=0, max_value=(1 << 256) - 1))
def test_unsigned_integer_byte_round_trip_property(value: int) -> None:
    encoded = integer_to_bytes(value)
    assert bytes_to_integer(bytes.fromhex(encoded.bytes_hex)).integer == value
