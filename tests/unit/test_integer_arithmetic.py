from __future__ import annotations

import pytest

from cryptolab.exceptions import MathematicalDomainError, ResourceLimitError
from cryptolab.limits import MAX_EDUCATIONAL_INTEGER
from cryptolab.mathematics.integers import (
    DivisorKind,
    divides,
    divisors,
    euclidean_algorithm,
    euclidean_division,
    extended_gcd,
    factor_integer,
    gcd,
    is_prime,
    lcm,
)


@pytest.mark.parametrize(
    ("dividend", "divisor", "quotient", "remainder"),
    [
        (17, 5, 3, 2),
        (-17, 5, -4, 3),
        (17, -5, -3, 2),
        (-17, -5, 4, 3),
        (0, 7, 0, 0),
        (10, 2, 5, 0),
    ],
)
def test_euclidean_division_convention(
    dividend: int,
    divisor: int,
    quotient: int,
    remainder: int,
) -> None:
    result = euclidean_division(dividend, divisor)
    assert result.quotient == quotient
    assert result.remainder == remainder
    assert result.identity_holds
    assert result.remainder_bound_holds


def test_euclidean_division_rejects_zero_divisor() -> None:
    with pytest.raises(MathematicalDomainError):
        euclidean_division(10, 0)


@pytest.mark.parametrize(
    ("divisor", "dividend", "expected"),
    [(5, 35, True), (-5, 35, True), (7, 0, True), (6, 35, False)],
)
def test_divides(divisor: int, dividend: int, expected: bool) -> None:
    assert divides(divisor, dividend) is expected


def test_divides_rejects_zero() -> None:
    with pytest.raises(MathematicalDomainError):
        divides(0, 0)


def test_divisor_enumeration() -> None:
    assert divisors(12) == (1, 2, 3, 4, 6, 12)
    assert divisors(-12, DivisorKind.NEGATIVE) == (-12, -6, -4, -3, -2, -1)
    assert divisors(12, DivisorKind.ALL) == (
        -12,
        -6,
        -4,
        -3,
        -2,
        -1,
        1,
        2,
        3,
        4,
        6,
        12,
    )


def test_divisors_reject_zero_and_excessive_values() -> None:
    with pytest.raises(MathematicalDomainError):
        divisors(0)
    with pytest.raises(ResourceLimitError):
        divisors(MAX_EDUCATIONAL_INTEGER + 1)


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (0, 0, 0),
        (42, 0, 42),
        (-42, 0, 42),
        (250, 110, 10),
        (-250, 110, 10),
    ],
)
def test_gcd(a: int, b: int, expected: int) -> None:
    assert gcd(a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [(0, 7, 0), (7, 0, 0), (12, 18, 36), (-12, 18, 36), (-12, -18, 36)],
)
def test_lcm(a: int, b: int, expected: int) -> None:
    assert lcm(a, b) == expected


def test_euclidean_algorithm_trace() -> None:
    result = euclidean_algorithm(250, 110)
    assert result.gcd == 10
    assert [
        (step.dividend, step.divisor, step.quotient, step.remainder) for step in result.steps
    ] == [
        (250, 110, 2, 30),
        (110, 30, 3, 20),
        (30, 20, 1, 10),
        (20, 10, 2, 0),
    ]


def test_euclidean_algorithm_with_zero_inputs() -> None:
    assert euclidean_algorithm(0, 0).gcd == 0
    assert euclidean_algorithm(0, 0).steps == ()
    assert euclidean_algorithm(0, 12).gcd == 12


@pytest.mark.parametrize(("a", "b"), [(250, 110), (-250, 110), (250, -110), (-250, -110)])
def test_extended_gcd_bezout_identity(a: int, b: int) -> None:
    result = extended_gcd(a, b)
    assert result.gcd == 10
    assert result.identity_holds


def test_extended_gcd_degenerate_cases() -> None:
    assert extended_gcd(0, 0) == extended_gcd(0, 0)
    assert extended_gcd(0, 0).x == 0
    assert extended_gcd(0, 0).y == 0
    assert extended_gcd(-9, 0).x == -1
    assert extended_gcd(0, -9).y == -1


@pytest.mark.parametrize(
    ("n", "expected", "divisor"),
    [
        (0, False, None),
        (1, False, None),
        (2, True, None),
        (3, True, None),
        (4, False, 2),
        (9, False, 3),
        (97, True, None),
        (221, False, 13),
    ],
)
def test_prime_testing(n: int, expected: bool, divisor: int | None) -> None:
    result = is_prime(n)
    assert result.is_prime is expected
    assert result.divisor == divisor


def test_prime_testing_rejects_negative_and_excessive_inputs() -> None:
    with pytest.raises(MathematicalDomainError):
        is_prime(-3)
    with pytest.raises(ResourceLimitError):
        is_prime(MAX_EDUCATIONAL_INTEGER + 1)


@pytest.mark.parametrize(
    ("n", "sign", "factors"),
    [
        (1, 1, ()),
        (-1, -1, ()),
        (97, 1, ((97, 1),)),
        (92400, 1, ((2, 4), (3, 1), (5, 2), (7, 1), (11, 1))),
        (-360, -1, ((2, 3), (3, 2), (5, 1))),
    ],
)
def test_factorization(n: int, sign: int, factors: tuple[tuple[int, int], ...]) -> None:
    result = factor_integer(n)
    assert result.sign == sign
    assert tuple((item.prime, item.exponent) for item in result.factors) == factors
    assert result.reconstructed == n


def test_factorization_rejects_zero_and_excessive_values() -> None:
    with pytest.raises(MathematicalDomainError):
        factor_integer(0)
    with pytest.raises(ResourceLimitError):
        factor_integer(MAX_EDUCATIONAL_INTEGER + 1)
