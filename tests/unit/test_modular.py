from __future__ import annotations

import pytest

from cryptolab.exceptions import MathematicalDomainError, ResourceLimitError
from cryptolab.mathematics.modular import (
    Congruence,
    generalized_crt,
    modular_add,
    modular_inverse,
    modular_multiply,
    modular_power,
    modular_subtract,
    normalize,
    solve_linear_congruence,
    units,
    zero_divisors,
)


def test_canonical_normalization() -> None:
    assert normalize(-9, 15) == 6
    assert normalize(31, 15) == 1


def test_basic_modular_operations() -> None:
    assert modular_add(14, 20, 9).value == 7
    assert modular_subtract(3, 10, 7).value == 0
    assert modular_multiply(12, 8, 13).value == 5


def test_modular_power_matches_builtin() -> None:
    result = modular_power(14, 15, 29)
    assert result.value == pow(14, 15, 29)
    assert result.steps


def test_zero_exponent() -> None:
    result = modular_power(123, 0, 17)
    assert result.value == 1
    assert result.steps == ()


def test_negative_exponent_rejected() -> None:
    with pytest.raises(MathematicalDomainError, match="non-negative exponents"):
        modular_power(2, -1, 7)


def test_inverse_exists() -> None:
    result = modular_inverse(13, 200)
    assert result.exists
    assert result.inverse == 77
    assert (13 * result.inverse) % 200 == 1


def test_inverse_does_not_exist() -> None:
    result = modular_inverse(54, 200)
    assert not result.exists
    assert result.inverse is None
    assert result.gcd == 2


def test_units_and_zero_divisors() -> None:
    assert units(15).values == (1, 2, 4, 7, 8, 11, 13, 14)
    assert zero_divisors(15).values == (3, 5, 6, 9, 10, 12)
    assert zero_divisors(11).values == ()


def test_enumeration_limit() -> None:
    with pytest.raises(ResourceLimitError, match="at most 4096"):
        units(4097)


def test_linear_congruence_unique_solution() -> None:
    result = solve_linear_congruence(3, 5, 7)
    assert result.solvable
    assert result.solutions == (4,)


def test_linear_congruence_multiple_solutions() -> None:
    result = solve_linear_congruence(15, 30, 55)
    assert result.solvable
    assert result.gcd == 5
    assert result.solutions == (2, 13, 24, 35, 46)


def test_linear_congruence_no_solution() -> None:
    result = solve_linear_congruence(9, 2, 36)
    assert not result.solvable
    assert result.solutions == ()


def test_linear_congruence_all_residues() -> None:
    result = solve_linear_congruence(0, 0, 5)
    assert result.solvable
    assert result.solutions == (0, 1, 2, 3, 4)


def test_coprime_crt() -> None:
    result = generalized_crt((Congruence(5, 7), Congruence(0, 6), Congruence(-1, 5)))
    assert result.solvable
    assert result.residue == 54
    assert result.modulus == 210


def test_generalized_non_coprime_crt() -> None:
    result = generalized_crt((Congruence(2, 6), Congruence(8, 9)))
    assert result.solvable
    assert result.residue == 8
    assert result.modulus == 18


def test_incompatible_crt() -> None:
    result = generalized_crt((Congruence(1, 4), Congruence(2, 6)))
    assert not result.solvable
    assert result.residue is None
    assert result.steps[-1].compatible is False


def test_single_congruence_crt() -> None:
    result = generalized_crt((Congruence(-1, 5),))
    assert result.solvable
    assert result.residue == 4
    assert result.modulus == 5


def test_crt_requires_input() -> None:
    with pytest.raises(MathematicalDomainError, match="at least one"):
        generalized_crt(())


def test_invalid_modulus() -> None:
    with pytest.raises(MathematicalDomainError, match="greater than or equal to 2"):
        normalize(3, 1)


def test_linear_congruence_solution_enumeration_limit() -> None:
    with pytest.raises(ResourceLimitError, match="more than 4096 solutions"):
        solve_linear_congruence(0, 0, 4097)
