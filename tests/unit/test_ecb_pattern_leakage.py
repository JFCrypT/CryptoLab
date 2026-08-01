from __future__ import annotations

import pytest

from cryptolab.exceptions import InputValidationError
from cryptolab.labs.ecb_pattern_leakage import run_ecb_pattern_leakage_lab


def test_ecb_pattern_leakage_preserves_repeated_block_equality() -> None:
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    result = run_ecb_pattern_leakage_lab(
        key=bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        plaintext=block + bytes(16) + block,
    )
    assert result.block_count == 3
    assert result.blocks[0].ciphertext_hex == result.blocks[2].ciphertext_hex
    assert result.repeated_pattern_preserved
    assert result.unique_plaintext_blocks == 2
    assert result.unique_ciphertext_blocks == 2


def test_ecb_pattern_leakage_requires_aligned_multiple_blocks() -> None:
    with pytest.raises(InputValidationError, match="at least two"):
        run_ecb_pattern_leakage_lab(key=bytes(16), plaintext=bytes(16))
    with pytest.raises(InputValidationError, match="block aligned"):
        run_ecb_pattern_leakage_lab(key=bytes(16), plaintext=bytes(33))
