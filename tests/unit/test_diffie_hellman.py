from __future__ import annotations

import pytest

from cryptolab.exceptions import MathematicalDomainError, ResourceLimitError
from cryptolab.public_key.diffie_hellman import inspect_dh_group, perform_dh_exchange


def test_course_finite_field_diffie_hellman_example() -> None:
    group = inspect_dh_group(17, 3)
    assert group.is_generator
    assert group.group_order == 16
    assert group.generator_order == 16
    assert all(check.passes for check in group.generator_checks)

    exchange = perform_dh_exchange(
        prime=17,
        generator=3,
        alice_private=13,
        bob_private=11,
    )
    assert exchange.alice_public == 12
    assert exchange.bob_public == 7
    assert exchange.alice_shared_secret == 6
    assert exchange.bob_shared_secret == 6
    assert exchange.shared_secret_matches
    assert exchange.shared_secret_hex == f"{exchange.alice_shared_secret:02x}"
    assert len(exchange.hkdf.okm_hex) == 64
    assert exchange.hkdf.complete_derivation_matches


def test_group_inspection_detects_non_generator() -> None:
    group = inspect_dh_group(17, 4)
    assert group.generator_order == 4
    assert not group.is_generator
    assert any(not check.passes for check in group.generator_checks)


def test_exchange_validates_group_and_private_exponents() -> None:
    with pytest.raises(MathematicalDomainError, match="requires a generator"):
        perform_dh_exchange(
            prime=17,
            generator=4,
            alice_private=13,
            bob_private=11,
        )
    with pytest.raises(MathematicalDomainError, match="Alice private exponent"):
        perform_dh_exchange(
            prime=17,
            generator=3,
            alice_private=1,
            bob_private=11,
        )
    with pytest.raises(MathematicalDomainError, match="Bob private exponent"):
        perform_dh_exchange(
            prime=17,
            generator=3,
            alice_private=13,
            bob_private=16,
        )


def test_group_validation_rejects_invalid_moduli_and_trivial_elements() -> None:
    with pytest.raises(MathematicalDomainError, match="must be prime"):
        inspect_dh_group(15, 2)
    with pytest.raises(MathematicalDomainError, match="at least 5"):
        inspect_dh_group(3, 2)
    with pytest.raises(MathematicalDomainError, match="non-trivial"):
        inspect_dh_group(17, 1)
    with pytest.raises(ResourceLimitError, match="at most 4096"):
        inspect_dh_group(65_537, 3)


def test_exchange_accepts_explicit_hkdf_context() -> None:
    exchange = perform_dh_exchange(
        prime=23,
        generator=5,
        alice_private=6,
        bob_private=15,
        salt=bytes.fromhex("00010203"),
        info=b"CryptoLab test",
        derived_key_length=16,
    )
    assert exchange.shared_secret_matches
    assert exchange.hkdf.salt_provided
    assert exchange.hkdf.info_hex == b"CryptoLab test".hex()
    assert exchange.hkdf.output_length == 16
    assert len(exchange.hkdf.okm_hex) == 32
