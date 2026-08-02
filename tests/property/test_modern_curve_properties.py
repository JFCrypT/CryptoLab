from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from hypothesis import given
from hypothesis import strategies as st

from cryptolab.public_key.modern_curves import ed25519_sign, ed25519_verify


@given(st.binary(max_size=512))
def test_ed25519_round_trip_for_arbitrary_messages(message: bytes) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    signed = ed25519_sign(private_key, message)
    assert ed25519_verify(
        private_key.public_key(), message, bytes.fromhex(signed.signature_hex)
    ).valid


@given(st.binary(min_size=32, max_size=32), st.binary(min_size=32, max_size=32))
def test_x25519_exchange_symmetry(alice_bytes: bytes, bob_bytes: bytes) -> None:
    alice = x25519.X25519PrivateKey.from_private_bytes(alice_bytes)
    bob = x25519.X25519PrivateKey.from_private_bytes(bob_bytes)
    alice_shared = alice.exchange(bob.public_key())
    bob_shared = bob.exchange(alice.public_key())
    assert alice_shared == bob_shared
