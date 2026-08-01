from __future__ import annotations

import pytest

from cryptolab.exceptions import AuthenticationError, InputValidationError
from cryptolab.symmetric.modern import (
    AESMode,
    PaddingMode,
    aead_profiles,
    aes_decrypt,
    aes_encrypt,
    aes_mode_profiles,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)

AES128_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
AES256_KEY = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
COUNTER = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")


@pytest.mark.parametrize(
    ("mode", "parameter_name", "expected_hex"),
    [
        (
            AESMode.ECB,
            None,
            "3ad77bb40d7a3660a89ecaf32466ef97"
            "f5d3d58503b9699de785895a96fdbaaf"
            "43b1cd7f598ece23881b00e3ed030688"
            "7b0c785e27e8ad3f8223207104725dd4",
        ),
        (
            AESMode.CBC,
            "iv",
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7",
        ),
        (
            AESMode.CFB128,
            "iv",
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "c8a64537a0b3a93fcde3cdad9f1ce58b"
            "26751f67a3cbb140b1808cf187a4f4df"
            "c04b05357c5d1c0eeac4c66f9ff7f2e6",
        ),
        (
            AESMode.OFB,
            "iv",
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "7789508d16918f03f53c52dac54ed825"
            "9740051e9c5fecf64344f7a82260edcc"
            "304c6528f659c77866a510d9c1d6ae5e",
        ),
        (
            AESMode.CTR,
            "counter",
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee",
        ),
    ],
)
def test_nist_sp_800_38a_vectors(
    mode: AESMode, parameter_name: str | None, expected_hex: str
) -> None:
    kwargs: dict[str, bytes] = {}
    if parameter_name == "iv":
        kwargs["iv"] = IV
    elif parameter_name == "counter":
        kwargs["counter"] = COUNTER
    encrypted = aes_encrypt(
        mode=mode,
        key=AES128_KEY,
        plaintext=PLAINTEXT,
        padding_mode=PaddingMode.NONE,
        **kwargs,
    )
    assert encrypted.output_hex == expected_hex
    decrypted = aes_decrypt(
        mode=mode,
        key=AES128_KEY,
        ciphertext=bytes.fromhex(expected_hex),
        padding_mode=PaddingMode.NONE,
        **kwargs,
    )
    assert decrypted.output_hex == PLAINTEXT.hex()


def test_aes_256_vector_and_pkcs7_round_trip() -> None:
    block = PLAINTEXT[:16]
    expected = "f3eed1bdb5d2a03c064b5a7e3db181f8"
    assert aes_encrypt(mode=AESMode.ECB, key=AES256_KEY, plaintext=block).output_hex == expected

    plaintext = b"CryptoLab CBC padding"
    encrypted = aes_encrypt(
        mode=AESMode.CBC,
        key=AES256_KEY,
        plaintext=plaintext,
        padding_mode=PaddingMode.PKCS7,
        iv=IV,
    )
    decrypted = aes_decrypt(
        mode=AESMode.CBC,
        key=AES256_KEY,
        ciphertext=bytes.fromhex(encrypted.output_hex),
        padding_mode=PaddingMode.PKCS7,
        iv=IV,
    )
    assert bytes.fromhex(decrypted.output_hex) == plaintext


def test_nist_gcm_vector_and_authentication_failure() -> None:
    key = bytes(16)
    nonce = bytes(12)
    plaintext = bytes(16)
    encrypted = aes_encrypt(
        mode=AESMode.GCM,
        key=key,
        plaintext=plaintext,
        nonce=nonce,
    )
    assert encrypted.output_hex == "0388dace60b6a392f328c2b971b2fe78"
    assert encrypted.tag_hex == "ab6e47d42cec13bdf53a67b21257bddf"
    decrypted = aes_decrypt(
        mode=AESMode.GCM,
        key=key,
        ciphertext=bytes.fromhex(encrypted.output_hex),
        nonce=nonce,
        tag=bytes.fromhex(encrypted.tag_hex),
    )
    assert decrypted.output_hex == plaintext.hex()
    with pytest.raises(AuthenticationError, match="authentication failed"):
        aes_decrypt(
            mode=AESMode.GCM,
            key=key,
            ciphertext=bytes.fromhex(encrypted.output_hex),
            nonce=nonce,
            tag=bytes.fromhex("00" * 16),
        )


def test_ieee_xts_vector_and_round_trip() -> None:
    key = bytes.fromhex("2718281828459045235360287471352631415926535897932384626433832795")
    tweak = bytes(16)
    plaintext = bytes(range(32))
    expected = "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c"
    encrypted = aes_encrypt(mode=AESMode.XTS, key=key, plaintext=plaintext, tweak=tweak)
    assert encrypted.output_hex == expected
    decrypted = aes_decrypt(
        mode=AESMode.XTS,
        key=key,
        ciphertext=bytes.fromhex(expected),
        tweak=tweak,
    )
    assert decrypted.output_hex == plaintext.hex()


def test_rfc_8439_chacha20_poly1305_vector() -> None:
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = bytes.fromhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f6620"
        "2739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e65207469"
        "7020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069"
        "742e"
    )
    expected_ciphertext = (
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
    )
    encrypted = chacha20_poly1305_encrypt(
        key=key,
        nonce=nonce,
        plaintext=plaintext,
        aad=aad,
    )
    assert encrypted.output_hex == expected_ciphertext
    assert encrypted.tag_hex == "1ae10b594f09e26a7e902ecbd0600691"
    decrypted = chacha20_poly1305_decrypt(
        key=key,
        nonce=nonce,
        ciphertext=bytes.fromhex(expected_ciphertext),
        tag=bytes.fromhex(encrypted.tag_hex),
        aad=aad,
    )
    assert decrypted.output_hex == plaintext.hex()
    with pytest.raises(AuthenticationError):
        chacha20_poly1305_decrypt(
            key=key,
            nonce=nonce,
            ciphertext=bytes.fromhex(expected_ciphertext),
            tag=bytes(16),
            aad=aad,
        )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"mode": AESMode.ECB, "key": b"x" * 24, "plaintext": b""}, "16 or 32"),
        (
            {"mode": AESMode.CBC, "key": b"x" * 16, "plaintext": b"abc"},
            "CBC IV is required",
        ),
        (
            {
                "mode": AESMode.CTR,
                "key": b"x" * 16,
                "plaintext": b"abc",
                "padding_mode": PaddingMode.PKCS7,
                "counter": bytes(16),
            },
            "does not use PKCS#7",
        ),
        (
            {"mode": AESMode.ECB, "key": b"x" * 16, "plaintext": b"abc"},
            "multiple of 16",
        ),
        (
            {
                "mode": AESMode.XTS,
                "key": b"a" * 32,
                "plaintext": bytes(16),
                "tweak": bytes(16),
            },
            "halves must not be identical",
        ),
        (
            {
                "mode": AESMode.XTS,
                "key": b"a" * 16 + b"b" * 16,
                "plaintext": b"short",
                "tweak": bytes(16),
            },
            "at least 16",
        ),
    ],
)
def test_aes_validation_errors(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(InputValidationError, match=message):
        aes_encrypt(**kwargs)  # type: ignore[arg-type]


def test_additional_decryption_and_parameter_validation() -> None:
    with pytest.raises(InputValidationError, match="ciphertext length"):
        aes_decrypt(mode=AESMode.CBC, key=bytes(16), ciphertext=b"x", iv=bytes(16))
    with pytest.raises(InputValidationError, match="tag is not used"):
        aes_decrypt(
            mode=AESMode.CTR,
            key=bytes(16),
            ciphertext=b"x",
            counter=bytes(16),
            tag=bytes(16),
        )
    with pytest.raises(InputValidationError, match="Nonce is not used"):
        aes_encrypt(
            mode=AESMode.ECB,
            key=bytes(16),
            plaintext=bytes(16),
            nonce=bytes(12),
        )
    encrypted = aes_encrypt(
        mode=AESMode.CBC,
        key=bytes(16),
        plaintext=b"valid padding",
        padding_mode=PaddingMode.PKCS7,
        iv=bytes(16),
    )
    damaged = bytearray.fromhex(encrypted.output_hex)
    damaged[-1] ^= 1
    with pytest.raises(InputValidationError, match="padding is invalid"):
        aes_decrypt(
            mode=AESMode.CBC,
            key=bytes(16),
            ciphertext=bytes(damaged),
            padding_mode=PaddingMode.PKCS7,
            iv=bytes(16),
        )


def test_chacha_parameter_validation() -> None:
    with pytest.raises(InputValidationError, match="32 bytes"):
        chacha20_poly1305_encrypt(key=bytes(16), nonce=bytes(12), plaintext=b"")
    with pytest.raises(InputValidationError, match="12 bytes"):
        chacha20_poly1305_encrypt(key=bytes(32), nonce=bytes(8), plaintext=b"")
    with pytest.raises(InputValidationError, match="16 bytes"):
        chacha20_poly1305_decrypt(key=bytes(32), nonce=bytes(12), ciphertext=b"", tag=bytes(8))


def test_comparison_profiles_cover_approved_scope() -> None:
    assert [item.mode for item in aes_mode_profiles()] == [
        "ECB",
        "CBC",
        "CFB-128",
        "OFB",
        "CTR",
        "GCM",
        "XTS",
    ]
    assert [item.algorithm for item in aead_profiles()] == [
        "AES-GCM",
        "ChaCha20-Poly1305",
    ]
