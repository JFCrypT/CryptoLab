"""Transparent finite-field Diffie-Hellman over deliberately small prime fields."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.exceptions import MathematicalDomainError, ResourceLimitError
from cryptolab.hashing.hkdf_sha256 import HKDFResult, derive_hkdf_sha256
from cryptolab.limits import MAX_ENUMERATED_MODULUS
from cryptolab.mathematics.algebra import GroupOperation, element_order
from cryptolab.mathematics.integers import factor_integer, is_prime
from cryptolab.mathematics.modular import ModularPowerStep, modular_power

DEFAULT_DH_HKDF_INFO_TEXT = "CryptoLab finite-field Diffie-Hellman"
DEFAULT_DH_HKDF_INFO = DEFAULT_DH_HKDF_INFO_TEXT.encode("utf-8")
DEFAULT_DH_DERIVED_KEY_BYTES = 32
MIN_DH_PRIME = 5
MIN_DH_PRIVATE_EXPONENT = 2


@dataclass(frozen=True, slots=True)
class DHGeneratorCheck:
    """One prime-factor test used to validate a primitive root modulo ``p``."""

    prime_factor: int
    exponent: int
    value: int
    passes: bool


@dataclass(frozen=True, slots=True)
class DHGroupResult:
    """Validated educational Diffie-Hellman group parameters."""

    prime: int
    generator: int
    group_order: int
    generator_order: int
    is_prime_modulus: bool
    is_generator: bool
    generator_checks: tuple[DHGeneratorCheck, ...]


@dataclass(frozen=True, slots=True)
class DHExchangeResult:
    """Complete educational finite-field Diffie-Hellman exchange."""

    group: DHGroupResult
    alice_private: int
    bob_private: int
    alice_public: int
    bob_public: int
    alice_public_order: int
    bob_public_order: int
    alice_shared_secret: int
    bob_shared_secret: int
    shared_secret_matches: bool
    shared_secret_hex: str
    hkdf: HKDFResult
    alice_public_steps: tuple[ModularPowerStep, ...]
    bob_public_steps: tuple[ModularPowerStep, ...]
    alice_shared_steps: tuple[ModularPowerStep, ...]
    bob_shared_steps: tuple[ModularPowerStep, ...]


def _validate_prime(prime: int) -> None:
    if prime < MIN_DH_PRIME:
        raise MathematicalDomainError(
            f"Educational Diffie-Hellman requires a prime modulus at least {MIN_DH_PRIME}."
        )
    if prime > MAX_ENUMERATED_MODULUS:
        raise ResourceLimitError(
            "Educational Diffie-Hellman group inspection accepts prime moduli at most "
            f"{MAX_ENUMERATED_MODULUS}."
        )
    result = is_prime(prime)
    if not result.is_prime:
        detail = f"; divisor {result.divisor}" if result.divisor is not None else ""
        raise MathematicalDomainError(f"Diffie-Hellman modulus must be prime{detail}.")


def _build_generator_check(
    *,
    prime: int,
    generator: int,
    group_order: int,
    prime_factor: int,
) -> DHGeneratorCheck:
    exponent = group_order // prime_factor
    value = pow(generator, exponent, prime)
    return DHGeneratorCheck(
        prime_factor=prime_factor,
        exponent=exponent,
        value=value,
        passes=value != 1,
    )


def inspect_dh_group(prime: int, generator: int) -> DHGroupResult:
    """Inspect whether ``generator`` is a primitive root modulo the small prime ``prime``."""

    _validate_prime(prime)
    normalized_generator = generator % prime
    if normalized_generator in {0, 1}:
        raise MathematicalDomainError(
            "Diffie-Hellman generator must represent a non-trivial element of Z_p^*."
        )

    group_order = prime - 1
    factorization = factor_integer(group_order)
    checks = tuple(
        _build_generator_check(
            prime=prime,
            generator=normalized_generator,
            group_order=group_order,
            prime_factor=factor.prime,
        )
        for factor in factorization.factors
    )
    generator_order = element_order(
        normalized_generator,
        prime,
        GroupOperation.MULTIPLICATIVE,
    ).order
    is_generator = generator_order == group_order and all(check.passes for check in checks)
    return DHGroupResult(
        prime=prime,
        generator=normalized_generator,
        group_order=group_order,
        generator_order=generator_order,
        is_prime_modulus=True,
        is_generator=is_generator,
        generator_checks=checks,
    )


def validate_dh_private_exponent(value: int, prime: int, *, label: str) -> None:
    """Validate a deliberately small private exponent for the educational exchange."""

    if not MIN_DH_PRIVATE_EXPONENT <= value <= prime - MIN_DH_PRIVATE_EXPONENT:
        raise MathematicalDomainError(
            f"{label} private exponent must satisfy 2 <= exponent <= p - 2."
        )


def perform_dh_exchange(
    *,
    prime: int,
    generator: int,
    alice_private: int,
    bob_private: int,
    salt: bytes | None = None,
    info: bytes = DEFAULT_DH_HKDF_INFO,
    derived_key_length: int = DEFAULT_DH_DERIVED_KEY_BYTES,
) -> DHExchangeResult:
    """Perform an inspectable finite-field Diffie-Hellman exchange and derive a key."""

    group = inspect_dh_group(prime, generator)
    if not group.is_generator:
        raise MathematicalDomainError(
            "Educational Diffie-Hellman exchange requires a generator of Z_p^*."
        )
    validate_dh_private_exponent(alice_private, prime, label="Alice")
    validate_dh_private_exponent(bob_private, prime, label="Bob")

    alice_public_result = modular_power(group.generator, alice_private, prime)
    bob_public_result = modular_power(group.generator, bob_private, prime)
    alice_shared_result = modular_power(bob_public_result.value, alice_private, prime)
    bob_shared_result = modular_power(alice_public_result.value, bob_private, prime)
    shared_secret_matches = alice_shared_result.value == bob_shared_result.value
    if not shared_secret_matches:  # pragma: no cover
        raise ArithmeticError("Internal Diffie-Hellman shared-secret invariant failure.")

    secret_length = max(1, (prime.bit_length() + 7) // 8)
    shared_secret_bytes = alice_shared_result.value.to_bytes(secret_length, "big")
    hkdf = derive_hkdf_sha256(
        ikm=shared_secret_bytes,
        salt=salt,
        info=info,
        length=derived_key_length,
    )

    return DHExchangeResult(
        group=group,
        alice_private=alice_private,
        bob_private=bob_private,
        alice_public=alice_public_result.value,
        bob_public=bob_public_result.value,
        alice_public_order=element_order(
            alice_public_result.value,
            prime,
            GroupOperation.MULTIPLICATIVE,
        ).order,
        bob_public_order=element_order(
            bob_public_result.value,
            prime,
            GroupOperation.MULTIPLICATIVE,
        ).order,
        alice_shared_secret=alice_shared_result.value,
        bob_shared_secret=bob_shared_result.value,
        shared_secret_matches=shared_secret_matches,
        shared_secret_hex=shared_secret_bytes.hex(),
        hkdf=hkdf,
        alice_public_steps=alice_public_result.steps,
        bob_public_steps=bob_public_result.steps,
        alice_shared_steps=alice_shared_result.steps,
        bob_shared_steps=bob_shared_result.steps,
    )
