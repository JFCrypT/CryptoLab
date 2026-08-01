from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from cryptolab.symmetric.modern import (
    AESMode,
    aes_decrypt,
    aes_encrypt,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)


@given(
    key=st.binary(min_size=16, max_size=16),
    plaintext=st.binary(min_size=0, max_size=128),
    counter=st.binary(min_size=16, max_size=16),
)
def test_aes_ctr_round_trip_property(key: bytes, plaintext: bytes, counter: bytes) -> None:
    encrypted = aes_encrypt(
        mode=AESMode.CTR,
        key=key,
        plaintext=plaintext,
        counter=counter,
    )
    decrypted = aes_decrypt(
        mode=AESMode.CTR,
        key=key,
        ciphertext=bytes.fromhex(encrypted.output_hex),
        counter=counter,
    )
    assert decrypted.output_hex == plaintext.hex()


@given(
    key=st.binary(min_size=32, max_size=32),
    nonce=st.binary(min_size=12, max_size=12),
    plaintext=st.binary(min_size=0, max_size=128),
    aad=st.binary(min_size=0, max_size=64),
)
def test_chacha20_poly1305_round_trip_property(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
) -> None:
    encrypted = chacha20_poly1305_encrypt(
        key=key,
        nonce=nonce,
        plaintext=plaintext,
        aad=aad,
    )
    decrypted = chacha20_poly1305_decrypt(
        key=key,
        nonce=nonce,
        ciphertext=bytes.fromhex(encrypted.output_hex),
        tag=bytes.fromhex(encrypted.tag_hex or ""),
        aad=aad,
    )
    assert decrypted.output_hex == plaintext.hex()
