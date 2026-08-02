"""Transparent educational RSA arithmetic over deliberately small integers."""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd as math_gcd
from secrets import randbits

from cryptolab.exceptions import (
    InputValidationError,
    MathematicalDomainError,
    ResourceLimitError,
)
from cryptolab.mathematics.integers import is_prime, lcm
from cryptolab.mathematics.modular import ModularPowerStep, modular_power

SMALLEST_PRIME = 2
MIN_EDUCATIONAL_RSA_PRIME_BITS = 4
MAX_EDUCATIONAL_RSA_PRIME_BITS = 20
MAX_EDUCATIONAL_RSA_GENERATION_ATTEMPTS = 100_000
DEFAULT_EDUCATIONAL_RSA_PUBLIC_EXPONENT = 65_537


@dataclass(frozen=True, slots=True)
class EducationalRSAKey:
    """Complete educational RSA key material and CRT parameters."""

    p: int
    q: int
    n: int
    phi: int
    carmichael: int
    e: int
    d: int
    d_carmichael: int
    dp: int
    dq: int
    q_inverse_mod_p: int
    p_inverse_mod_q: int


@dataclass(frozen=True, slots=True)
class EducationalRSAOperationResult:
    """One textbook RSA modular-exponentiation operation."""

    operation: str
    input_value: int
    output_value: int
    exponent: int
    modulus: int
    steps: tuple[ModularPowerStep, ...]
    deterministic: bool


@dataclass(frozen=True, slots=True)
class EducationalRSADecryptionResult:
    """Textbook RSA decryption with standard and CRT reconstruction values."""

    ciphertext: int
    plaintext: int
    standard_plaintext: int
    crt_plaintext: int
    m1: int
    m2: int
    h: int
    standard_steps: tuple[ModularPowerStep, ...]
    crt_matches_standard: bool


@dataclass(frozen=True, slots=True)
class EducationalRSAGenerationResult:
    """Generated educational RSA key and bounded generation metadata."""

    key: EducationalRSAKey
    prime_bits: int
    attempts: int
    randomness: str


@dataclass(frozen=True, slots=True)
class IntegerBytesResult:
    """Unsigned big-endian integer/byte conversion result."""

    operation: str
    integer: int
    bytes_hex: str
    length: int
    byte_order: str
    signed: bool


def _validate_small_prime(value: int, *, label: str) -> None:
    if value < SMALLEST_PRIME:
        raise MathematicalDomainError(f"{label} must be a positive prime integer.")
    if value.bit_length() > MAX_EDUCATIONAL_RSA_PRIME_BITS:
        raise ResourceLimitError(
            f"{label} must not exceed {MAX_EDUCATIONAL_RSA_PRIME_BITS} bits in educational RSA."
        )
    result = is_prime(value)
    if not result.is_prime:
        detail = f"; divisor {result.divisor}" if result.divisor is not None else ""
        raise MathematicalDomainError(f"{label} must be prime{detail}.")


def build_educational_rsa_key(p: int, q: int, e: int) -> EducationalRSAKey:
    """Build a transparent textbook RSA key from two small distinct primes."""

    _validate_small_prime(p, label="p")
    _validate_small_prime(q, label="q")
    if p == q:
        raise MathematicalDomainError("Educational RSA requires two distinct primes p and q.")

    n = p * q
    phi = (p - 1) * (q - 1)
    carmichael = lcm(p - 1, q - 1)
    if not 1 < e < phi:
        raise MathematicalDomainError("Educational RSA requires 1 < e < phi(n).")
    if math_gcd(e, phi) != 1:
        raise MathematicalDomainError("Educational RSA requires gcd(e, phi(n)) = 1.")

    d = pow(e, -1, phi)
    d_carmichael = pow(e, -1, carmichael)
    key = EducationalRSAKey(
        p=p,
        q=q,
        n=n,
        phi=phi,
        carmichael=carmichael,
        e=e,
        d=d,
        d_carmichael=d_carmichael,
        dp=d % (p - 1),
        dq=d % (q - 1),
        q_inverse_mod_p=pow(q, -1, p),
        p_inverse_mod_q=pow(p, -1, q),
    )
    if (key.e * key.d) % key.phi != 1:  # pragma: no cover
        raise ArithmeticError("Internal RSA inverse invariant failure.")
    return key


def _random_odd_candidate(bits: int) -> int:
    candidate = randbits(bits)
    candidate |= 1 << (bits - 1)
    candidate |= 1
    return candidate


def _generate_prime(bits: int, attempts_used: int) -> tuple[int, int]:
    attempts = attempts_used
    while attempts < MAX_EDUCATIONAL_RSA_GENERATION_ATTEMPTS:
        attempts += 1
        candidate = _random_odd_candidate(bits)
        if is_prime(candidate).is_prime:
            return candidate, attempts
    raise ResourceLimitError(
        "Educational RSA prime generation exceeded the configured attempt limit."
    )


def generate_educational_rsa_key(
    *,
    prime_bits: int,
    e: int = DEFAULT_EDUCATIONAL_RSA_PUBLIC_EXPONENT,
) -> EducationalRSAGenerationResult:
    """Generate two small primes and a compatible educational RSA key."""

    if not MIN_EDUCATIONAL_RSA_PRIME_BITS <= prime_bits <= MAX_EDUCATIONAL_RSA_PRIME_BITS:
        raise InputValidationError(
            "Educational RSA prime size must be between "
            f"{MIN_EDUCATIONAL_RSA_PRIME_BITS} and {MAX_EDUCATIONAL_RSA_PRIME_BITS} bits."
        )
    if e <= 1 or e % 2 == 0:
        raise MathematicalDomainError(
            "Educational RSA public exponent e must be an odd integer > 1."
        )

    attempts = 0
    while attempts < MAX_EDUCATIONAL_RSA_GENERATION_ATTEMPTS:
        p, attempts = _generate_prime(prime_bits, attempts)
        q, attempts = _generate_prime(prime_bits, attempts)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if e >= phi or math_gcd(e, phi) != 1:
            continue
        return EducationalRSAGenerationResult(
            key=build_educational_rsa_key(p, q, e),
            prime_bits=prime_bits,
            attempts=attempts,
            randomness="Python secrets.randbits",
        )
    raise ResourceLimitError(
        "Educational RSA key generation exceeded the configured attempt limit."
    )


def _validate_rsa_representative(value: int, key: EducationalRSAKey, *, label: str) -> None:
    if not 0 <= value < key.n:
        raise MathematicalDomainError(f"{label} must satisfy 0 <= {label} < n.")


def textbook_rsa_encrypt(message: int, key: EducationalRSAKey) -> EducationalRSAOperationResult:
    """Encrypt one integer representative with deterministic textbook RSA."""

    _validate_rsa_representative(message, key, label="message")
    power = modular_power(message, key.e, key.n)
    return EducationalRSAOperationResult(
        operation="encrypt",
        input_value=message,
        output_value=power.value,
        exponent=key.e,
        modulus=key.n,
        steps=power.steps,
        deterministic=True,
    )


def textbook_rsa_decrypt(
    ciphertext: int,
    key: EducationalRSAKey,
) -> EducationalRSADecryptionResult:
    """Decrypt one integer representative and expose CRT reconstruction."""

    _validate_rsa_representative(ciphertext, key, label="ciphertext")
    standard = modular_power(ciphertext, key.d, key.n)
    m1 = pow(ciphertext, key.dp, key.p)
    m2 = pow(ciphertext, key.dq, key.q)
    h = (key.q_inverse_mod_p * (m1 - m2)) % key.p
    crt_plaintext = m2 + h * key.q
    result = EducationalRSADecryptionResult(
        ciphertext=ciphertext,
        plaintext=crt_plaintext,
        standard_plaintext=standard.value,
        crt_plaintext=crt_plaintext,
        m1=m1,
        m2=m2,
        h=h,
        standard_steps=standard.steps,
        crt_matches_standard=crt_plaintext == standard.value,
    )
    if not result.crt_matches_standard:  # pragma: no cover
        raise ArithmeticError("Internal RSA CRT reconstruction invariant failure.")
    return result


def integer_to_bytes(value: int, *, length: int | None = None) -> IntegerBytesResult:
    """Convert a non-negative integer to unsigned big-endian bytes."""

    if value < 0:
        raise MathematicalDomainError("Integer-to-bytes conversion accepts non-negative integers.")
    minimal_length = max(1, (value.bit_length() + 7) // 8)
    target_length = minimal_length if length is None else length
    if target_length < 1:
        raise InputValidationError("Requested byte length must be at least 1.")
    if target_length < minimal_length:
        raise InputValidationError(
            f"Integer requires at least {minimal_length} bytes; "
            f"requested length is {target_length}."
        )
    encoded = value.to_bytes(target_length, byteorder="big", signed=False)
    return IntegerBytesResult(
        operation="integer-to-bytes",
        integer=value,
        bytes_hex=encoded.hex(),
        length=len(encoded),
        byte_order="big",
        signed=False,
    )


def bytes_to_integer(data: bytes) -> IntegerBytesResult:
    """Convert non-empty bytes to an unsigned big-endian integer."""

    if not data:
        raise InputValidationError("Bytes-to-integer conversion requires at least one byte.")
    value = int.from_bytes(data, byteorder="big", signed=False)
    return IntegerBytesResult(
        operation="bytes-to-integer",
        integer=value,
        bytes_hex=data.hex(),
        length=len(data),
        byte_order="big",
        signed=False,
    )
