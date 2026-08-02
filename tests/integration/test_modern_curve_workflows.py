from __future__ import annotations

from cryptolab.public_key.modern_curves import (
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_key_pair,
    generate_x25519_key_pair,
    load_ed25519_private_key,
    load_ed25519_public_key,
    load_x25519_private_key,
    perform_x25519_exchange,
)


def test_generated_x25519_keys_derive_the_same_session_key() -> None:
    alice_material = generate_x25519_key_pair()
    bob_material = generate_x25519_key_pair()
    result = perform_x25519_exchange(
        alice_private_key=load_x25519_private_key(alice_material.private_pem),
        bob_private_key=load_x25519_private_key(bob_material.private_pem),
        salt=b"CryptoLab salt",
        info=b"integration session",
        derived_key_length=32,
    )
    assert result.shared_secret_matches
    assert result.alice_shared_secret_hex == result.bob_shared_secret_hex
    assert result.hkdf.complete_derivation_matches
    assert len(result.hkdf.okm_hex) == 64


def test_generated_ed25519_keys_sign_and_verify() -> None:
    material = generate_ed25519_key_pair()
    private_key = load_ed25519_private_key(material.private_pem)
    public_key = load_ed25519_public_key(material.public_pem)
    message = b"CryptoLab integration"
    signature = ed25519_sign(private_key, message)
    assert ed25519_verify(public_key, message, bytes.fromhex(signature.signature_hex)).valid
    assert not ed25519_verify(
        public_key,
        message + b" changed",
        bytes.fromhex(signature.signature_hex),
    ).valid
