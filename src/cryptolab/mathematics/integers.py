"""Transparent educational implementations of elementary integer arithmetic."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from math import gcd as math_gcd
from math import isqrt

from cryptolab.exceptions import MathematicalDomainError, ResourceLimitError
from cryptolab.limits import MAX_EDUCATIONAL_INTEGER, MAX_INTEGER_BITS, MAX_TRACE_ROWS

MIN_PRIME = 2


class DivisorKind(StrEnum):
    """Supported divisor enumeration policies."""

    POSITIVE = "positive"
    NEGATIVE = "negative"
    ALL = "all"


@dataclass(frozen=True, slots=True)
class EuclideanDivisionResult:
    """Result of Euclidean division under CryptoLab's remainder convention."""

    dividend: int
    divisor: int
    quotient: int
    remainder: int

    @property
    def identity_holds(self) -> bool:
        """Return whether ``dividend = divisor * quotient + remainder`` holds."""

        return self.dividend == self.divisor * self.quotient + self.remainder

    @property
    def remainder_bound_holds(self) -> bool:
        """Return whether ``0 <= remainder < abs(divisor)`` holds."""

        return 0 <= self.remainder < abs(self.divisor)


@dataclass(frozen=True, slots=True)
class EuclideanStep:
    """One division step of the Euclidean algorithm."""

    dividend: int
    divisor: int
    quotient: int
    remainder: int


@dataclass(frozen=True, slots=True)
class EuclideanAlgorithmResult:
    """Complete Euclidean-algorithm trace."""

    a: int
    b: int
    gcd: int
    steps: tuple[EuclideanStep, ...]


@dataclass(frozen=True, slots=True)
class ExtendedGCDStep:
    """One state transition of the iterative extended Euclidean algorithm."""

    quotient: int
    old_remainder: int
    remainder: int
    old_x: int
    x: int
    old_y: int
    y: int


@dataclass(frozen=True, slots=True)
class ExtendedGCDResult:
    """A gcd together with deterministic Bézout coefficients and a trace."""

    a: int
    b: int
    gcd: int
    x: int
    y: int
    steps: tuple[ExtendedGCDStep, ...]

    @property
    def identity_holds(self) -> bool:
        """Return whether the Bézout identity holds."""

        return self.a * self.x + self.b * self.y == self.gcd


@dataclass(frozen=True, slots=True)
class PrimeTestResult:
    """Result of deterministic educational trial-division primality testing."""

    n: int
    is_prime: bool
    divisor: int | None
    tested_candidates: int


@dataclass(frozen=True, slots=True)
class PrimePower:
    """One prime-power component of an integer factorization."""

    prime: int
    exponent: int


@dataclass(frozen=True, slots=True)
class FactorizationResult:
    """Canonical educational factorization of a non-zero integer."""

    n: int
    sign: int
    factors: tuple[PrimePower, ...]

    @property
    def reconstructed(self) -> int:
        """Reconstruct the input integer from the stored sign and prime powers."""

        value = self.sign
        for factor in self.factors:
            value *= factor.prime**factor.exponent
        return value


def _validate_integer_size(*values: int) -> None:
    for value in values:
        if value.bit_length() > MAX_INTEGER_BITS:
            raise ResourceLimitError(
                f"Integer input exceeds the {MAX_INTEGER_BITS}-bit general arithmetic limit."
            )


def _validate_educational_bound(n: int, operation: str) -> None:
    if abs(n) > MAX_EDUCATIONAL_INTEGER:
        raise ResourceLimitError(
            f"{operation} accepts only integers with absolute value at most "
            f"{MAX_EDUCATIONAL_INTEGER}."
        )


def euclidean_division(dividend: int, divisor: int) -> EuclideanDivisionResult:
    """Return ``q`` and ``r`` such that ``a = bq + r`` and ``0 <= r < |b|``.

    Python's native ``divmod`` uses a remainder with the sign of the divisor. CryptoLab
    instead fixes a non-negative Euclidean remainder even when the divisor is negative.
    """

    _validate_integer_size(dividend, divisor)
    if divisor == 0:
        raise MathematicalDomainError("Euclidean division is undefined for divisor zero.")

    quotient_for_positive_divisor, remainder = divmod(dividend, abs(divisor))
    quotient = quotient_for_positive_divisor if divisor > 0 else -quotient_for_positive_divisor
    result = EuclideanDivisionResult(dividend, divisor, quotient, remainder)

    if not result.identity_holds or not result.remainder_bound_holds:  # pragma: no cover
        raise ArithmeticError("Internal Euclidean-division invariant failure.")
    return result


def divides(divisor: int, dividend: int) -> bool:
    """Return whether a non-zero integer ``divisor`` divides ``dividend``."""

    _validate_integer_size(divisor, dividend)
    if divisor == 0:
        raise MathematicalDomainError("Zero is excluded as a divisor in CryptoLab.")
    return dividend % divisor == 0


def divisors(n: int, kind: DivisorKind = DivisorKind.POSITIVE) -> tuple[int, ...]:
    """Enumerate positive, negative, or all integer divisors of a non-zero integer."""

    _validate_educational_bound(n, "Divisor enumeration")
    if n == 0:
        raise MathematicalDomainError(
            "Divisors of zero are not enumerated because every non-zero integer divides zero."
        )

    absolute = abs(n)
    lower: list[int] = []
    upper: list[int] = []
    for candidate in range(1, isqrt(absolute) + 1):
        if absolute % candidate == 0:
            lower.append(candidate)
            paired = absolute // candidate
            if paired != candidate:
                upper.append(paired)

    positive = tuple(lower + list(reversed(upper)))
    negative = tuple(-value for value in reversed(positive))

    if kind is DivisorKind.POSITIVE:
        return positive
    if kind is DivisorKind.NEGATIVE:
        return negative
    return negative + positive


def gcd(a: int, b: int) -> int:
    """Return the non-negative greatest common divisor, including ``gcd(0, 0) = 0``."""

    _validate_integer_size(a, b)
    return math_gcd(a, b)


def lcm(a: int, b: int) -> int:
    """Return the non-negative least common multiple, with zero if either input is zero."""

    _validate_integer_size(a, b)
    if a == 0 or b == 0:
        return 0
    return abs((a // math_gcd(a, b)) * b)


def euclidean_algorithm(a: int, b: int) -> EuclideanAlgorithmResult:
    """Compute the gcd and expose each Euclidean division step."""

    _validate_integer_size(a, b)
    left, right = abs(a), abs(b)
    if left < right:
        left, right = right, left

    steps: list[EuclideanStep] = []
    while right != 0:
        quotient, remainder = divmod(left, right)
        steps.append(EuclideanStep(left, right, quotient, remainder))
        if len(steps) > MAX_TRACE_ROWS:  # pragma: no cover
            raise ResourceLimitError("Euclidean trace exceeds the configured row limit.")
        left, right = right, remainder

    return EuclideanAlgorithmResult(a=a, b=b, gcd=left, steps=tuple(steps))


def extended_gcd(a: int, b: int) -> ExtendedGCDResult:
    """Return deterministic Bézout coefficients and an iterative execution trace."""

    _validate_integer_size(a, b)

    if a == 0 and b == 0:
        return ExtendedGCDResult(a=0, b=0, gcd=0, x=0, y=0, steps=())
    if b == 0:
        return ExtendedGCDResult(a=a, b=0, gcd=abs(a), x=1 if a > 0 else -1, y=0, steps=())
    if a == 0:
        return ExtendedGCDResult(a=0, b=b, gcd=abs(b), x=0, y=1 if b > 0 else -1, steps=())

    old_r, remainder = abs(a), abs(b)
    old_x, x = 1, 0
    old_y, y = 0, 1
    steps: list[ExtendedGCDStep] = []

    while remainder != 0:
        quotient = old_r // remainder
        steps.append(
            ExtendedGCDStep(
                quotient=quotient,
                old_remainder=old_r,
                remainder=remainder,
                old_x=old_x,
                x=x,
                old_y=old_y,
                y=y,
            )
        )
        old_r, remainder = remainder, old_r - quotient * remainder
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
        if len(steps) > MAX_TRACE_ROWS:  # pragma: no cover
            raise ResourceLimitError("Extended-gcd trace exceeds the configured row limit.")

    coefficient_x = old_x if a > 0 else -old_x
    coefficient_y = old_y if b > 0 else -old_y
    result = ExtendedGCDResult(
        a=a,
        b=b,
        gcd=old_r,
        x=coefficient_x,
        y=coefficient_y,
        steps=tuple(steps),
    )
    if not result.identity_holds:  # pragma: no cover
        raise ArithmeticError("Internal Bézout-identity invariant failure.")
    return result


def is_prime(n: int) -> PrimeTestResult:
    """Test primality deterministically by educational trial division up to ``sqrt(n)``."""

    if n < 0:
        raise MathematicalDomainError("Primality testing accepts non-negative integers only.")
    _validate_educational_bound(n, "Primality testing")

    if n < MIN_PRIME:
        return PrimeTestResult(n=n, is_prime=False, divisor=None, tested_candidates=0)
    if n in (2, 3):
        return PrimeTestResult(n=n, is_prime=True, divisor=None, tested_candidates=0)
    if n % 2 == 0:
        return PrimeTestResult(n=n, is_prime=False, divisor=2, tested_candidates=1)
    if n % 3 == 0:
        return PrimeTestResult(n=n, is_prime=False, divisor=3, tested_candidates=2)

    tested = 2
    candidate = 5
    step = 2
    limit = isqrt(n)
    while candidate <= limit:
        tested += 1
        if n % candidate == 0:
            return PrimeTestResult(
                n=n,
                is_prime=False,
                divisor=candidate,
                tested_candidates=tested,
            )
        candidate += step
        step = 6 - step

    return PrimeTestResult(n=n, is_prime=True, divisor=None, tested_candidates=tested)


def factor_integer(n: int) -> FactorizationResult:
    """Factor a bounded non-zero integer by deterministic educational trial division."""

    _validate_educational_bound(n, "Educational factorization")
    if n == 0:
        raise MathematicalDomainError("Zero has no prime factorization.")

    sign = -1 if n < 0 else 1
    remainder = abs(n)
    factors: list[PrimePower] = []

    for prime in (2, 3):
        exponent = 0
        while remainder % prime == 0 and remainder > 1:
            remainder //= prime
            exponent += 1
        if exponent:
            factors.append(PrimePower(prime=prime, exponent=exponent))

    candidate = 5
    step = 2
    while candidate * candidate <= remainder:
        exponent = 0
        while remainder % candidate == 0:
            remainder //= candidate
            exponent += 1
        if exponent:
            factors.append(PrimePower(prime=candidate, exponent=exponent))
        candidate += step
        step = 6 - step

    if remainder > 1:
        factors.append(PrimePower(prime=remainder, exponent=1))

    result = FactorizationResult(n=n, sign=sign, factors=tuple(factors))
    if result.reconstructed != n:  # pragma: no cover
        raise ArithmeticError("Internal factorization invariant failure.")
    return result
