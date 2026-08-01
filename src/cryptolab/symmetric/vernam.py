"""Educational Vernam encryption and decryption using equal-length XOR."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.symmetric.xor import ByteXORStep, xor_bytes


@dataclass(frozen=True, slots=True)
class VernamResult:
    """Vernam transformation result."""

    operation: str
    input_hex: str
    key_hex: str
    output_hex: str
    input_bits: str
    key_bits: str
    output_bits: str
    length_bytes: int
    steps: tuple[ByteXORStep, ...]


def _transform(data: bytes, key: bytes, *, operation: str) -> VernamResult:
    result = xor_bytes(data, key)
    return VernamResult(
        operation=operation,
        input_hex=result.left_hex,
        key_hex=result.right_hex,
        output_hex=result.output_hex,
        input_bits=result.left_bits,
        key_bits=result.right_bits,
        output_bits=result.output_bits,
        length_bytes=result.length_bytes,
        steps=result.steps,
    )


def vernam_encrypt(message: bytes, key: bytes) -> VernamResult:
    """Encrypt bytes with an equal-length Vernam key."""

    return _transform(message, key, operation="encrypt")


def vernam_decrypt(ciphertext: bytes, key: bytes) -> VernamResult:
    """Decrypt bytes with the same equal-length Vernam key."""

    return _transform(ciphertext, key, operation="decrypt")
