"""Controlled Vernam key-reuse laboratory."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.symmetric.vernam import vernam_encrypt
from cryptolab.symmetric.xor import xor_bytes


@dataclass(frozen=True, slots=True)
class VernamKeyReuseLabResult:
    """Consequence of encrypting two messages with the same Vernam keystream."""

    identifier: str
    message_one_hex: str
    message_two_hex: str
    reused_key_hex: str
    ciphertext_one_hex: str
    ciphertext_two_hex: str
    ciphertext_xor_hex: str
    plaintext_xor_hex: str
    identity_holds: bool
    violated_assumption: str
    security_effect: str
    mitigation: str


def run_vernam_key_reuse_lab(
    message_one: bytes,
    message_two: bytes,
    reused_key: bytes,
) -> VernamKeyReuseLabResult:
    """Demonstrate C1 XOR C2 = M1 XOR M2 under keystream reuse."""

    ciphertext_one = bytes.fromhex(vernam_encrypt(message_one, reused_key).output_hex)
    ciphertext_two = bytes.fromhex(vernam_encrypt(message_two, reused_key).output_hex)
    ciphertext_xor = xor_bytes(ciphertext_one, ciphertext_two).output_hex
    plaintext_xor = xor_bytes(message_one, message_two).output_hex
    return VernamKeyReuseLabResult(
        identifier="vernam-key-reuse",
        message_one_hex=message_one.hex(),
        message_two_hex=message_two.hex(),
        reused_key_hex=reused_key.hex(),
        ciphertext_one_hex=ciphertext_one.hex(),
        ciphertext_two_hex=ciphertext_two.hex(),
        ciphertext_xor_hex=ciphertext_xor,
        plaintext_xor_hex=plaintext_xor,
        identity_holds=ciphertext_xor == plaintext_xor,
        violated_assumption="The same keystream was used for more than one message.",
        security_effect="The XOR of the ciphertexts reveals the XOR of the plaintexts.",
        mitigation="Never reuse One-Time Pad material or a stream-cipher nonce/key pair.",
    )
