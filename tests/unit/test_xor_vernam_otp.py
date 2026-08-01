from __future__ import annotations

import pytest

from cryptolab.exceptions import InputValidationError
from cryptolab.symmetric.otp import otp_requirements
from cryptolab.symmetric.vernam import vernam_decrypt, vernam_encrypt
from cryptolab.symmetric.xor import xor_bits, xor_bytes, xor_truth_table


def test_xor_truth_table_and_bitwise_operation() -> None:
    rows = xor_truth_table()
    assert [(row.left, row.right, row.result) for row in rows] == [
        (0, 0, 0),
        (0, 1, 1),
        (1, 0, 1),
        (1, 1, 0),
    ]
    result = xor_bits("1011", "1111")
    assert result.output == "0100"
    assert xor_bits(result.output, "1111").output == "1011"


def test_bytewise_xor_and_vernam_example() -> None:
    xor_result = xor_bytes(bytes.fromhex("beca"), bytes.fromhex("fe12"))
    assert xor_result.output_hex == "40d8"
    assert xor_result.output_bits == "0100000011011000"

    encrypted = vernam_encrypt(bytes.fromhex("beca"), bytes.fromhex("fe12"))
    assert encrypted.output_hex == "40d8"
    decrypted = vernam_decrypt(bytes.fromhex(encrypted.output_hex), bytes.fromhex("fe12"))
    assert decrypted.output_hex == "beca"


def test_xor_rejects_unequal_lengths() -> None:
    with pytest.raises(InputValidationError, match="equal length"):
        xor_bits("1", "00")
    with pytest.raises(InputValidationError, match="equal length"):
        xor_bytes(b"A", b"AB")


def test_otp_requirements_are_complete() -> None:
    requirements = otp_requirements()
    assert len(requirements) == 6
    identifiers = {item.identifier for item in requirements}
    assert identifiers == {
        "uniform-random-key",
        "key-length",
        "one-time-use",
        "secure-distribution",
        "secure-storage",
        "secure-destruction",
    }
