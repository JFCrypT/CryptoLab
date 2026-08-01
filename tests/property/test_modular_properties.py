from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from cryptolab.mathematics.modular import (
    Congruence,
    generalized_crt,
    modular_inverse,
    modular_power,
    normalize,
    solve_linear_congruence,
)

integer = st.integers(min_value=-(1 << 63), max_value=(1 << 63) - 1)
modulus = st.integers(min_value=2, max_value=500)


@given(value=integer, n=modulus)
def test_normalization_is_canonical_and_congruent(value: int, n: int) -> None:
    representative = normalize(value, n)
    assert 0 <= representative < n
    assert (value - representative) % n == 0


@given(base=integer, exponent=st.integers(min_value=0, max_value=500), n=modulus)
def test_modular_power_matches_python(base: int, exponent: int, n: int) -> None:
    assert modular_power(base, exponent, n).value == pow(base, exponent, n)


@given(value=integer, n=modulus)
def test_inverse_result_is_correct(value: int, n: int) -> None:
    result = modular_inverse(value, n)
    if result.exists:
        assert result.inverse is not None
        assert value * result.inverse % n == 1


@given(a=integer, b=integer, n=modulus)
def test_linear_congruence_returns_exact_solutions(a: int, b: int, n: int) -> None:
    result = solve_linear_congruence(a, b, n)
    brute_force = tuple(x for x in range(n) if (a * x - b) % n == 0)
    assert result.solutions == brute_force
    assert result.solvable is bool(brute_force)


@given(
    residue=integer,
    first_modulus=modulus,
    second_modulus=modulus,
)
def test_crt_recovers_a_shared_constructed_residue(
    residue: int,
    first_modulus: int,
    second_modulus: int,
) -> None:
    result = generalized_crt(
        (
            Congruence(residue, first_modulus),
            Congruence(residue, second_modulus),
        )
    )
    assert result.solvable
    assert result.residue is not None
    assert result.residue % first_modulus == residue % first_modulus
    assert result.residue % second_modulus == residue % second_modulus
