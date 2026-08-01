from __future__ import annotations

import pytest

from cryptolab.labs.ecb_pattern_leakage import run_ecb_pattern_leakage_lab
from cryptolab.symmetric.modern import (
    AESMode,
    PaddingMode,
    aes_decrypt,
    aes_encrypt,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)


@pytest.mark.parametrize(
    ("mode", "kwargs"),
    [
        (AESMode.ECB, {}),
        (AESMode.CBC, {"iv": bytes(range(16))}),
        (AESMode.CFB128, {"iv": bytes(range(16))}),
        (AESMode.OFB, {"iv": bytes(range(16))}),
        (AESMode.CTR, {"counter": bytes(range(16))}),
    ],
)
def test_aes_128_round_trip_workflow(mode: AESMode, kwargs: dict[str, bytes]) -> None:
    plaintext = bytes(range(32))
    encrypted = aes_encrypt(mode=mode, key=bytes(range(16)), plaintext=plaintext, **kwargs)
    decrypted = aes_decrypt(
        mode=mode,
        key=bytes(range(16)),
        ciphertext=bytes.fromhex(encrypted.output_hex),
        **kwargs,
    )
    assert decrypted.output_hex == plaintext.hex()


def test_authenticated_encryption_workflows() -> None:
    plaintext = b"CryptoLab authenticated encryption"
    aad = b"metadata"
    aes = aes_encrypt(
        mode=AESMode.GCM,
        key=bytes(range(32)),
        plaintext=plaintext,
        nonce=bytes(range(12)),
        aad=aad,
    )
    assert (
        aes_decrypt(
            mode=AESMode.GCM,
            key=bytes(range(32)),
            ciphertext=bytes.fromhex(aes.output_hex),
            nonce=bytes(range(12)),
            aad=aad,
            tag=bytes.fromhex(aes.tag_hex or ""),
        ).output_hex
        == plaintext.hex()
    )

    chacha = chacha20_poly1305_encrypt(
        key=bytes(range(32)),
        nonce=bytes(range(12)),
        plaintext=plaintext,
        aad=aad,
    )
    assert (
        chacha20_poly1305_decrypt(
            key=bytes(range(32)),
            nonce=bytes(range(12)),
            ciphertext=bytes.fromhex(chacha.output_hex),
            tag=bytes.fromhex(chacha.tag_hex or ""),
            aad=aad,
        ).output_hex
        == plaintext.hex()
    )


def test_pkcs7_and_ecb_laboratory_share_library_backed_aes() -> None:
    plaintext = b"not block aligned"
    encrypted = aes_encrypt(
        mode=AESMode.CBC,
        key=bytes(range(16)),
        plaintext=plaintext,
        padding_mode=PaddingMode.PKCS7,
        iv=bytes(range(16)),
    )
    assert (
        aes_decrypt(
            mode=AESMode.CBC,
            key=bytes(range(16)),
            ciphertext=bytes.fromhex(encrypted.output_hex),
            padding_mode=PaddingMode.PKCS7,
            iv=bytes(range(16)),
        ).output_hex
        == plaintext.hex()
    )

    repeated = bytes(range(16)) * 3
    lab = run_ecb_pattern_leakage_lab(key=bytes(range(16)), plaintext=repeated)
    assert lab.repeated_pattern_preserved
