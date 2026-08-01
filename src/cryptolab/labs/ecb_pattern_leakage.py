"""Controlled demonstration of repeated-block leakage in AES-ECB."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.exceptions import InputValidationError
from cryptolab.symmetric.modern import AES_BLOCK_BYTES, AESMode, PaddingMode, aes_encrypt

MIN_ECB_LAB_BLOCKS = 2
MIN_REPEATED_OCCURRENCES = 2


@dataclass(frozen=True, slots=True)
class ECBBlockPair:
    """One plaintext block and its corresponding ciphertext block."""

    index: int
    plaintext_hex: str
    ciphertext_hex: str


@dataclass(frozen=True, slots=True)
class ECBPatternLeakageResult:
    """Repeated-block evidence produced by the controlled ECB laboratory."""

    plaintext_hex: str
    ciphertext_hex: str
    block_count: int
    unique_plaintext_blocks: int
    unique_ciphertext_blocks: int
    repeated_plaintext_blocks: tuple[str, ...]
    repeated_ciphertext_blocks: tuple[str, ...]
    repeated_pattern_preserved: bool
    blocks: tuple[ECBBlockPair, ...]
    violated_assumption: str
    security_effect: str
    mitigation: str


def _repeated(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(value for value in values if values.count(value) >= MIN_REPEATED_OCCURRENCES)
    )


def run_ecb_pattern_leakage_lab(*, key: bytes, plaintext: bytes) -> ECBPatternLeakageResult:
    """Encrypt aligned local blocks and expose deterministic equality leakage."""

    if len(plaintext) < AES_BLOCK_BYTES * MIN_ECB_LAB_BLOCKS:
        raise InputValidationError("ECB leakage laboratory requires at least two plaintext blocks.")
    if len(plaintext) % AES_BLOCK_BYTES != 0:
        raise InputValidationError("ECB leakage laboratory plaintext must be block aligned.")
    encrypted = aes_encrypt(
        mode=AESMode.ECB,
        key=key,
        plaintext=plaintext,
        padding_mode=PaddingMode.NONE,
    )
    ciphertext = bytes.fromhex(encrypted.output_hex)
    plaintext_blocks = tuple(
        plaintext[index : index + AES_BLOCK_BYTES].hex()
        for index in range(0, len(plaintext), AES_BLOCK_BYTES)
    )
    ciphertext_blocks = tuple(
        ciphertext[index : index + AES_BLOCK_BYTES].hex()
        for index in range(0, len(ciphertext), AES_BLOCK_BYTES)
    )
    repeated_plaintext = _repeated(plaintext_blocks)
    repeated_ciphertext = _repeated(ciphertext_blocks)
    blocks = tuple(
        ECBBlockPair(index, plaintext_block, ciphertext_blocks[index])
        for index, plaintext_block in enumerate(plaintext_blocks)
    )
    return ECBPatternLeakageResult(
        plaintext_hex=plaintext.hex(),
        ciphertext_hex=ciphertext.hex(),
        block_count=len(plaintext_blocks),
        unique_plaintext_blocks=len(set(plaintext_blocks)),
        unique_ciphertext_blocks=len(set(ciphertext_blocks)),
        repeated_plaintext_blocks=repeated_plaintext,
        repeated_ciphertext_blocks=repeated_ciphertext,
        repeated_pattern_preserved=bool(repeated_plaintext)
        and len(repeated_plaintext) == len(repeated_ciphertext),
        blocks=blocks,
        violated_assumption="ECB deterministically encrypts equal plaintext blocks under one key.",
        security_effect="Repeated ciphertext blocks reveal repeated plaintext structure.",
        mitigation=(
            "Use a suitable authenticated-encryption construction such as AES-GCM or "
            "ChaCha20-Poly1305."
        ),
    )
