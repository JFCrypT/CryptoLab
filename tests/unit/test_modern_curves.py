from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from cryptolab.exceptions import InputValidationError
from cryptolab.public_key.modern_curves import (
    ed25519_private_key_from_raw,
    ed25519_public_key_from_raw,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_key_pair,
    generate_x25519_key_pair,
    key_agreement_profiles,
    load_ed25519_private_key,
    load_ed25519_public_key,
    load_x25519_private_key,
    load_x25519_public_key,
    perform_x25519_exchange,
    signature_profiles,
    x25519_private_key_from_raw,
    x25519_public_key_from_raw,
)

ALICE_X25519_PRIVATE = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
ALICE_X25519_PUBLIC = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
BOB_X25519_PRIVATE = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
BOB_X25519_PUBLIC = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
X25519_SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
ED25519_PRIVATE = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
ED25519_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
ED25519_SIGNATURE = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def test_x25519_generation_serialization_and_loading() -> None:
    material = generate_x25519_key_pair()
    assert material.algorithm == "X25519"
    assert material.private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert material.public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert len(material.public_key_hex) == 64
    assert len(material.public_fingerprint_sha256) == 64
    private_key = load_x25519_private_key(material.private_pem)
    public_key = load_x25519_public_key(material.public_pem)
    assert isinstance(private_key, x25519.X25519PrivateKey)
    assert isinstance(public_key, x25519.X25519PublicKey)


def test_x25519_rfc_7748_exchange_vector() -> None:
    alice = x25519_private_key_from_raw(bytes.fromhex(ALICE_X25519_PRIVATE))
    bob = x25519_private_key_from_raw(bytes.fromhex(BOB_X25519_PRIVATE))
    result = perform_x25519_exchange(
        alice_private_key=alice,
        bob_private_key=bob,
        salt=None,
        info=b"CryptoLab vector",
        derived_key_length=32,
    )
    assert result.alice_public_hex == ALICE_X25519_PUBLIC
    assert result.bob_public_hex == BOB_X25519_PUBLIC
    assert result.alice_shared_secret_hex == X25519_SHARED
    assert result.bob_shared_secret_hex == X25519_SHARED
    assert result.shared_secret_matches
    assert not result.all_zero_shared_secret
    assert len(result.hkdf.okm_hex) == 64


def test_x25519_raw_and_pem_validation() -> None:
    assert isinstance(
        x25519_public_key_from_raw(bytes.fromhex(ALICE_X25519_PUBLIC)),
        x25519.X25519PublicKey,
    )
    with pytest.raises(InputValidationError, match="exactly 32"):
        x25519_private_key_from_raw(b"short")
    with pytest.raises(InputValidationError, match="exactly 32"):
        x25519_public_key_from_raw(b"short")
    with pytest.raises(InputValidationError, match="parse"):
        load_x25519_private_key(b"not pem")
    with pytest.raises(InputValidationError, match="parse"):
        load_x25519_public_key(b"not pem")

    ed_material = generate_ed25519_key_pair()
    with pytest.raises(InputValidationError, match="does not contain an X25519"):
        load_x25519_private_key(ed_material.private_pem)
    with pytest.raises(InputValidationError, match="does not contain an X25519"):
        load_x25519_public_key(ed_material.public_pem)


def test_ed25519_generation_serialization_and_rfc_8032_vector() -> None:
    material = generate_ed25519_key_pair()
    assert material.algorithm == "Ed25519"
    assert material.private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert material.public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    private_key = load_ed25519_private_key(material.private_pem)
    public_key = load_ed25519_public_key(material.public_pem)
    assert isinstance(private_key, ed25519.Ed25519PrivateKey)
    assert isinstance(public_key, ed25519.Ed25519PublicKey)

    vector_private = ed25519_private_key_from_raw(bytes.fromhex(ED25519_PRIVATE))
    signature = ed25519_sign(vector_private, b"")
    assert signature.public_key_hex == ED25519_PUBLIC
    assert signature.signature_hex == ED25519_SIGNATURE
    assert signature.signature_length_bytes == 64
    assert signature.deterministic
    vector_public = ed25519_public_key_from_raw(bytes.fromhex(ED25519_PUBLIC))
    assert ed25519_verify(vector_public, b"", bytes.fromhex(ED25519_SIGNATURE)).valid
    assert not ed25519_verify(vector_public, b"changed", bytes.fromhex(ED25519_SIGNATURE)).valid


def test_ed25519_validation_and_determinism() -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    first = ed25519_sign(private_key, b"message")
    second = ed25519_sign(private_key, b"message")
    assert first.signature_hex == second.signature_hex
    with pytest.raises(InputValidationError, match="exactly 32"):
        ed25519_private_key_from_raw(b"short")
    with pytest.raises(InputValidationError, match="exactly 32"):
        ed25519_public_key_from_raw(b"short")
    with pytest.raises(InputValidationError, match="exactly 64"):
        ed25519_verify(private_key.public_key(), b"message", b"short")
    with pytest.raises(InputValidationError, match="parse"):
        load_ed25519_private_key(b"not pem")
    with pytest.raises(InputValidationError, match="parse"):
        load_ed25519_public_key(b"not pem")

    x_material = generate_x25519_key_pair()
    with pytest.raises(InputValidationError, match="does not contain an Ed25519"):
        load_ed25519_private_key(x_material.private_pem)
    with pytest.raises(InputValidationError, match="does not contain an Ed25519"):
        load_ed25519_public_key(x_material.public_pem)


def test_curve_comparison_profiles() -> None:
    agreements = key_agreement_profiles()
    assert [item.construction for item in agreements] == [
        "Finite-field Diffie-Hellman",
        "X25519",
    ]
    assert all(item.authentication == "None by itself" for item in agreements)
    signatures = signature_profiles()
    assert [item.construction for item in signatures] == [
        "RSA-PSS",
        "Ed25519",
        "HMAC-SHA-256",
    ]
    assert signatures[1].output_size == "64 bytes"
    assert "not a signature" in signatures[2].principal_limitation
