"""Controlled unauthenticated Diffie-Hellman man-in-the-middle laboratory."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.hashing.hkdf_sha256 import derive_hkdf_sha256
from cryptolab.public_key.diffie_hellman import (
    DEFAULT_DH_DERIVED_KEY_BYTES,
    perform_dh_exchange,
    validate_dh_private_exponent,
)

MITM_HKDF_INFO = b"CryptoLab unauthenticated finite-field DH"


@dataclass(frozen=True, slots=True)
class DHManInTheMiddleResult:
    """Two attacker-controlled DH channels replacing one honest exchange."""

    prime: int
    generator: int
    alice_private: int
    bob_private: int
    mallory_alice_private: int
    mallory_bob_private: int
    alice_public: int
    bob_public: int
    honest_shared_secret: int
    mallory_public_to_alice: int
    mallory_public_to_bob: int
    alice_channel_secret: int
    mallory_alice_secret: int
    bob_channel_secret: int
    mallory_bob_secret: int
    alice_channel_matches: bool
    bob_channel_matches: bool
    alice_bob_secrets_differ: bool
    alice_channel_key_hex: str
    mallory_alice_key_hex: str
    bob_channel_key_hex: str
    mallory_bob_key_hex: str
    violated_assumption: str
    security_effect: str
    mitigation: str


def _derive_channel_key(secret: int, prime: int) -> str:
    length = max(1, (prime.bit_length() + 7) // 8)
    return derive_hkdf_sha256(
        ikm=secret.to_bytes(length, "big"),
        salt=None,
        info=MITM_HKDF_INFO,
        length=DEFAULT_DH_DERIVED_KEY_BYTES,
    ).okm_hex


def run_dh_man_in_the_middle_lab(
    *,
    prime: int,
    generator: int,
    alice_private: int,
    bob_private: int,
    mallory_alice_private: int,
    mallory_bob_private: int,
) -> DHManInTheMiddleResult:
    """Replace both unauthenticated public values and establish two attacker-known keys."""

    honest = perform_dh_exchange(
        prime=prime,
        generator=generator,
        alice_private=alice_private,
        bob_private=bob_private,
    )
    group = honest.group
    validate_dh_private_exponent(mallory_alice_private, prime, label="Mallory-Alice")
    validate_dh_private_exponent(mallory_bob_private, prime, label="Mallory-Bob")

    mallory_public_to_alice = pow(group.generator, mallory_alice_private, prime)
    mallory_public_to_bob = pow(group.generator, mallory_bob_private, prime)

    alice_channel_secret = pow(mallory_public_to_alice, alice_private, prime)
    mallory_alice_secret = pow(honest.alice_public, mallory_alice_private, prime)
    bob_channel_secret = pow(mallory_public_to_bob, bob_private, prime)
    mallory_bob_secret = pow(honest.bob_public, mallory_bob_private, prime)

    if alice_channel_secret != mallory_alice_secret:  # pragma: no cover
        raise ArithmeticError("Internal Alice-Mallory DH invariant failure.")
    if bob_channel_secret != mallory_bob_secret:  # pragma: no cover
        raise ArithmeticError("Internal Bob-Mallory DH invariant failure.")

    alice_channel_key = _derive_channel_key(alice_channel_secret, prime)
    mallory_alice_key = _derive_channel_key(mallory_alice_secret, prime)
    bob_channel_key = _derive_channel_key(bob_channel_secret, prime)
    mallory_bob_key = _derive_channel_key(mallory_bob_secret, prime)

    return DHManInTheMiddleResult(
        prime=prime,
        generator=group.generator,
        alice_private=alice_private,
        bob_private=bob_private,
        mallory_alice_private=mallory_alice_private,
        mallory_bob_private=mallory_bob_private,
        alice_public=honest.alice_public,
        bob_public=honest.bob_public,
        honest_shared_secret=honest.alice_shared_secret,
        mallory_public_to_alice=mallory_public_to_alice,
        mallory_public_to_bob=mallory_public_to_bob,
        alice_channel_secret=alice_channel_secret,
        mallory_alice_secret=mallory_alice_secret,
        bob_channel_secret=bob_channel_secret,
        mallory_bob_secret=mallory_bob_secret,
        alice_channel_matches=alice_channel_secret == mallory_alice_secret,
        bob_channel_matches=bob_channel_secret == mallory_bob_secret,
        alice_bob_secrets_differ=alice_channel_secret != bob_channel_secret,
        alice_channel_key_hex=alice_channel_key,
        mallory_alice_key_hex=mallory_alice_key,
        bob_channel_key_hex=bob_channel_key,
        mallory_bob_key_hex=mallory_bob_key,
        violated_assumption="The exchanged Diffie-Hellman public values were not authenticated.",
        security_effect=(
            "Mallory replaces both public values and obtains one shared key with Alice and "
            "another shared key with Bob."
        ),
        mitigation=(
            "Authenticate the key agreement, for example by signing the transcript or by "
            "using an authenticated protocol."
        ),
    )
