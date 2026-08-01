from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from cryptolab.mathematics.integers import euclidean_division, extended_gcd, gcd, lcm

bounded = st.integers(min_value=-(1 << 63), max_value=(1 << 63) - 1)
nonzero = bounded.filter(lambda value: value != 0)


@given(a=bounded, b=nonzero)
def test_euclidean_division_properties(a: int, b: int) -> None:
    result = euclidean_division(a, b)
    assert a == b * result.quotient + result.remainder
    assert 0 <= result.remainder < abs(b)


@given(a=bounded, b=bounded)
def test_extended_gcd_properties(a: int, b: int) -> None:
    result = extended_gcd(a, b)
    assert result.gcd == gcd(a, b)
    assert a * result.x + b * result.y == result.gcd


@given(a=bounded, b=bounded)
def test_gcd_lcm_identity(a: int, b: int) -> None:
    assert gcd(a, b) * lcm(a, b) == abs(a * b)
