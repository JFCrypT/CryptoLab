"""Educational modular arithmetic over canonical residue representatives."""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd as math_gcd
from typing import TYPE_CHECKING

from cryptolab.exceptions import MathematicalDomainError, ResourceLimitError
from cryptolab.limits import MAX_CRT_CONGRUENCES, MAX_ENUMERATED_MODULUS, MAX_INTEGER_BITS
from cryptolab.mathematics.integers import extended_gcd

if TYPE_CHECKING:
    from collections.abc import Sequence

MIN_MODULUS = 2


@dataclass(frozen=True, slots=True)
class ModularScalarResult:
    """Result of a basic modular operation."""

    operation: str
    modulus: int
    value: int


@dataclass(frozen=True, slots=True)
class ModularPowerStep:
    """One right-to-left square-and-multiply transition."""

    exponent: int
    bit: int
    accumulator: int
    base: int


@dataclass(frozen=True, slots=True)
class ModularPowerResult:
    """Fast modular exponentiation result and optional educational trace."""

    base: int
    exponent: int
    modulus: int
    value: int
    steps: tuple[ModularPowerStep, ...]


@dataclass(frozen=True, slots=True)
class ModularInverseResult:
    """Existence and canonical value of a multiplicative inverse."""

    value: int
    modulus: int
    gcd: int
    exists: bool
    inverse: int | None
    bezout_x: int


@dataclass(frozen=True, slots=True)
class ResidueCollectionResult:
    """A named collection of canonical residues modulo ``n``."""

    kind: str
    modulus: int
    values: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class LinearCongruenceResult:
    """Complete solution set of ``ax ≡ b (mod n)``."""

    a: int
    b: int
    modulus: int
    gcd: int
    solvable: bool
    reduced_a: int | None
    reduced_b: int | None
    reduced_modulus: int | None
    base_solution: int | None
    solutions: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Congruence:
    """One canonical congruence ``x ≡ residue (mod modulus)``."""

    residue: int
    modulus: int


@dataclass(frozen=True, slots=True)
class CRTMergeStep:
    """One merge operation in the generalized Chinese Remainder Theorem."""

    left_residue: int
    left_modulus: int
    right_residue: int
    right_modulus: int
    gcd: int
    difference: int
    compatible: bool
    multiplier: int | None
    merged_residue: int | None
    merged_modulus: int | None


@dataclass(frozen=True, slots=True)
class CRTResult:
    """Generalized Chinese Remainder Theorem result."""

    congruences: tuple[Congruence, ...]
    solvable: bool
    residue: int | None
    modulus: int | None
    steps: tuple[CRTMergeStep, ...]


def _validate_integer_size(*values: int) -> None:
    for value in values:
        if value.bit_length() > MAX_INTEGER_BITS:
            raise ResourceLimitError(
                f"Integer input exceeds the {MAX_INTEGER_BITS}-bit general arithmetic limit."
            )


def _validate_modulus(modulus: int) -> None:
    _validate_integer_size(modulus)
    if modulus < MIN_MODULUS:
        raise MathematicalDomainError("A modulus must be an integer greater than or equal to 2.")


def normalize(value: int, modulus: int) -> int:
    """Return the canonical representative in ``{0, ..., modulus - 1}``."""

    _validate_integer_size(value)
    _validate_modulus(modulus)
    return value % modulus


def modular_add(a: int, b: int, modulus: int) -> ModularScalarResult:
    """Add two integers modulo ``modulus``."""

    _validate_integer_size(a, b)
    value = (normalize(a, modulus) + normalize(b, modulus)) % modulus
    return ModularScalarResult("add", modulus, value)


def modular_subtract(a: int, b: int, modulus: int) -> ModularScalarResult:
    """Subtract two integers modulo ``modulus``."""

    _validate_integer_size(a, b)
    return ModularScalarResult(
        "subtract",
        modulus,
        (normalize(a, modulus) - normalize(b, modulus)) % modulus,
    )


def modular_multiply(a: int, b: int, modulus: int) -> ModularScalarResult:
    """Multiply two integers modulo ``modulus``."""

    _validate_integer_size(a, b)
    return ModularScalarResult(
        "multiply",
        modulus,
        (normalize(a, modulus) * normalize(b, modulus)) % modulus,
    )


def modular_power(base: int, exponent: int, modulus: int) -> ModularPowerResult:
    """Compute ``base**exponent mod modulus`` by right-to-left square-and-multiply."""

    _validate_integer_size(base, exponent)
    _validate_modulus(modulus)
    if exponent < 0:
        raise MathematicalDomainError(
            "Fast modular exponentiation accepts non-negative exponents; invert first for "
            "negative powers."
        )

    current_base = base % modulus
    current_exponent = exponent
    accumulator = 1 % modulus
    steps: list[ModularPowerStep] = []

    while current_exponent > 0:
        bit = current_exponent & 1
        if bit:
            accumulator = (accumulator * current_base) % modulus
        current_base = (current_base * current_base) % modulus
        steps.append(
            ModularPowerStep(
                exponent=current_exponent,
                bit=bit,
                accumulator=accumulator,
                base=current_base,
            )
        )
        current_exponent >>= 1

    result = ModularPowerResult(
        base=base,
        exponent=exponent,
        modulus=modulus,
        value=accumulator,
        steps=tuple(steps),
    )
    if result.value != pow(base, exponent, modulus):  # pragma: no cover
        raise ArithmeticError("Internal modular-exponentiation invariant failure.")
    return result


def modular_inverse(value: int, modulus: int) -> ModularInverseResult:
    """Return the canonical multiplicative inverse when it exists."""

    _validate_integer_size(value)
    _validate_modulus(modulus)
    bezout = extended_gcd(value, modulus)
    exists = bezout.gcd == 1
    inverse = bezout.x % modulus if exists else None
    return ModularInverseResult(
        value=value,
        modulus=modulus,
        gcd=bezout.gcd,
        exists=exists,
        inverse=inverse,
        bezout_x=bezout.x,
    )


def units(modulus: int) -> ResidueCollectionResult:
    """Enumerate the multiplicative units of ``Z_n`` for a bounded modulus."""

    _validate_modulus(modulus)
    if modulus > MAX_ENUMERATED_MODULUS:
        raise ResourceLimitError(
            f"Residue enumeration accepts moduli at most {MAX_ENUMERATED_MODULUS}."
        )
    values = tuple(value for value in range(1, modulus) if math_gcd(value, modulus) == 1)
    return ResidueCollectionResult("units", modulus, values)


def zero_divisors(modulus: int) -> ResidueCollectionResult:
    """Enumerate non-zero zero divisors of ``Z_n`` for a bounded modulus."""

    _validate_modulus(modulus)
    if modulus > MAX_ENUMERATED_MODULUS:
        raise ResourceLimitError(
            f"Residue enumeration accepts moduli at most {MAX_ENUMERATED_MODULUS}."
        )
    values = tuple(value for value in range(1, modulus) if math_gcd(value, modulus) > 1)
    return ResidueCollectionResult("zero-divisors", modulus, values)


def solve_linear_congruence(a: int, b: int, modulus: int) -> LinearCongruenceResult:
    """Solve ``ax ≡ b (mod modulus)`` and return all incongruent canonical solutions."""

    _validate_integer_size(a, b)
    _validate_modulus(modulus)
    divisor = math_gcd(a, modulus)
    if b % divisor != 0:
        return LinearCongruenceResult(
            a=a,
            b=b,
            modulus=modulus,
            gcd=divisor,
            solvable=False,
            reduced_a=None,
            reduced_b=None,
            reduced_modulus=None,
            base_solution=None,
            solutions=(),
        )

    reduced_a = a // divisor
    reduced_b = b // divisor
    reduced_modulus = modulus // divisor
    if reduced_modulus == 1:
        base_solution = 0
    else:
        inverse = modular_inverse(reduced_a, reduced_modulus)
        if not inverse.exists or inverse.inverse is None:  # pragma: no cover
            raise ArithmeticError("Internal linear-congruence invariant failure.")
        base_solution = (inverse.inverse * reduced_b) % reduced_modulus
    if divisor > MAX_ENUMERATED_MODULUS:
        raise ResourceLimitError(
            f"Linear congruence would produce more than {MAX_ENUMERATED_MODULUS} solutions."
        )
    solutions = tuple(
        sorted((base_solution + index * reduced_modulus) % modulus for index in range(divisor))
    )
    return LinearCongruenceResult(
        a=a,
        b=b,
        modulus=modulus,
        gcd=divisor,
        solvable=True,
        reduced_a=reduced_a,
        reduced_b=reduced_b,
        reduced_modulus=reduced_modulus,
        base_solution=base_solution,
        solutions=solutions,
    )


def generalized_crt(congruences: Sequence[Congruence]) -> CRTResult:
    """Merge congruences using the generalized Chinese Remainder Theorem."""

    if not congruences:
        raise MathematicalDomainError("CRT requires at least one congruence.")
    if len(congruences) > MAX_CRT_CONGRUENCES:
        raise ResourceLimitError(
            f"CRT accepts at most {MAX_CRT_CONGRUENCES} congruences per operation."
        )

    canonical: list[Congruence] = []
    for item in congruences:
        _validate_modulus(item.modulus)
        _validate_integer_size(item.residue)
        canonical.append(Congruence(normalize(item.residue, item.modulus), item.modulus))

    current_residue = canonical[0].residue
    current_modulus = canonical[0].modulus
    steps: list[CRTMergeStep] = []

    for next_congruence in canonical[1:]:
        divisor = math_gcd(current_modulus, next_congruence.modulus)
        difference = next_congruence.residue - current_residue
        compatible = difference % divisor == 0
        if not compatible:
            steps.append(
                CRTMergeStep(
                    left_residue=current_residue,
                    left_modulus=current_modulus,
                    right_residue=next_congruence.residue,
                    right_modulus=next_congruence.modulus,
                    gcd=divisor,
                    difference=difference,
                    compatible=False,
                    multiplier=None,
                    merged_residue=None,
                    merged_modulus=None,
                )
            )
            return CRTResult(
                congruences=tuple(canonical),
                solvable=False,
                residue=None,
                modulus=None,
                steps=tuple(steps),
            )

        left_reduced = current_modulus // divisor
        right_reduced = next_congruence.modulus // divisor
        if right_reduced == 1:
            multiplier = 0
        else:
            inverse = modular_inverse(left_reduced, right_reduced)
            if not inverse.exists or inverse.inverse is None:  # pragma: no cover
                raise ArithmeticError("Internal CRT inverse invariant failure.")
            multiplier = ((difference // divisor) * inverse.inverse) % right_reduced

        merged_modulus = current_modulus * right_reduced
        if merged_modulus.bit_length() > MAX_INTEGER_BITS:
            raise ResourceLimitError(
                f"CRT result exceeds the {MAX_INTEGER_BITS}-bit general arithmetic limit."
            )
        merged_residue = (current_residue + current_modulus * multiplier) % merged_modulus
        steps.append(
            CRTMergeStep(
                left_residue=current_residue,
                left_modulus=current_modulus,
                right_residue=next_congruence.residue,
                right_modulus=next_congruence.modulus,
                gcd=divisor,
                difference=difference,
                compatible=True,
                multiplier=multiplier,
                merged_residue=merged_residue,
                merged_modulus=merged_modulus,
            )
        )
        current_residue = merged_residue
        current_modulus = merged_modulus

    return CRTResult(
        congruences=tuple(canonical),
        solvable=True,
        residue=current_residue,
        modulus=current_modulus,
        steps=tuple(steps),
    )
