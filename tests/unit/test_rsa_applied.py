from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptolab.exceptions import DecryptionError, InputValidationError
from cryptolab.public_key.rsa_applied import (
    generate_rsa_key_pair,
    load_rsa_private_key,
    load_rsa_public_key,
    rsa_oaep_decrypt,
    rsa_oaep_encrypt,
    rsa_oaep_maximum_message_bytes,
    rsa_profiles,
    rsa_pss_sign,
    rsa_pss_verify,
)


def test_applied_key_generation_and_serialization() -> None:
    material = generate_rsa_key_pair(key_size=2048)
    assert material.key_size_bits == 2048
    assert material.public_exponent == 65_537
    assert material.private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert material.public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert len(material.public_fingerprint_sha256) == 64
    assert not material.private_encrypted
    private_key = load_rsa_private_key(material.private_pem)
    public_key = load_rsa_public_key(material.public_pem)
    assert private_key.key_size == 2048
    assert public_key.public_numbers() == private_key.public_key().public_numbers()


def test_applied_key_size_and_key_type_validation() -> None:
    with pytest.raises(InputValidationError, match="2048, 3072, 4096"):
        generate_rsa_key_pair(key_size=1024)
    with pytest.raises(InputValidationError, match="parse"):
        load_rsa_public_key(b"not pem")
    with pytest.raises(InputValidationError, match="parse"):
        load_rsa_private_key(b"not pem")


def test_rsa_oaep_round_trip_and_message_bound() -> None:
    material = generate_rsa_key_pair(key_size=2048)
    private_key = load_rsa_private_key(material.private_pem)
    public_key = load_rsa_public_key(material.public_pem)
    assert rsa_oaep_maximum_message_bytes(public_key.key_size) == 190
    message = b"CryptoLab RSA-OAEP"
    encrypted = rsa_oaep_encrypt(public_key, message)
    assert encrypted.randomized
    assert encrypted.maximum_message_bytes == 190
    assert len(bytes.fromhex(encrypted.output_hex)) == 256
    decrypted = rsa_oaep_decrypt(private_key, bytes.fromhex(encrypted.output_hex))
    assert bytes.fromhex(decrypted.output_hex) == message


def test_rsa_oaep_is_randomized_and_rejects_invalid_inputs() -> None:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    public_key = private_key.public_key()
    first = rsa_oaep_encrypt(public_key, b"same")
    second = rsa_oaep_encrypt(public_key, b"same")
    assert first.output_hex != second.output_hex
    with pytest.raises(InputValidationError, match="must not exceed 190"):
        rsa_oaep_encrypt(public_key, bytes(191))
    with pytest.raises(InputValidationError, match="exactly 256"):
        rsa_oaep_decrypt(private_key, bytes(255))
    with pytest.raises(DecryptionError, match="decryption failed"):
        rsa_oaep_decrypt(private_key, bytes(256))


def test_rsa_pss_sign_verify_and_randomization() -> None:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    public_key = private_key.public_key()
    first = rsa_pss_sign(private_key, b"message")
    second = rsa_pss_sign(private_key, b"message")
    assert first.signature_hex != second.signature_hex
    assert rsa_pss_verify(public_key, b"message", bytes.fromhex(first.signature_hex)).valid
    assert not rsa_pss_verify(public_key, b"changed", bytes.fromhex(first.signature_hex)).valid
    with pytest.raises(InputValidationError, match="exactly 256"):
        rsa_pss_verify(public_key, b"message", bytes(255))


def test_rsa_comparison_profiles() -> None:
    profiles = rsa_profiles()
    assert [item.construction for item in profiles] == [
        "Textbook RSA",
        "RSA-OAEP",
        "RSA-PSS",
    ]
    assert profiles[0].category == "educational"
    assert profiles[1].purpose.startswith("Encrypt")
    assert "authenticity" in profiles[2].principal_limitation
