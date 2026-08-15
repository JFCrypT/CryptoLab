from __future__ import annotations

import pytest

from cryptolab.exceptions import InputValidationError, ResourceLimitError
from cryptolab.post_quantum.foundations import (
    MAX_EDUCATIONAL_MODULUS,
    MAX_RING_DEGREE,
    MAX_TOY_LWE_DIMENSION,
    negacyclic_multiply,
    toy_lwe_sample,
)


def test_negacyclic_multiplication_reduces_x_power_with_negative_sign() -> None:
    result = negacyclic_multiply((1, 2), (3, 4), modulus=17)
    # (1 + 2x)(3 + 4x) = 3 + 10x + 8x^2 and x^2 = -1.
    assert result.left == (1, 2)
    assert result.right == (3, 4)
    assert result.result == (12, 10)
    assert result.degree == 2
    assert any(term.raw_degree == 2 and term.sign == -1 for term in result.terms)


def test_negacyclic_multiplication_canonicalizes_coefficients() -> None:
    result = negacyclic_multiply((-1, 18), (1, -2), modulus=17)
    assert result.left == (16, 1)
    assert result.right == (1, 15)
    assert all(0 <= value < 17 for value in result.result)


@pytest.mark.parametrize(
    ("left", "right", "modulus", "match"),
    [
        ((), (), 17, "must not be empty"),
        ((1,), (1, 2), 17, "equal length"),
        ((1,), (1,), 1, "at least 2"),
    ],
)
def test_negacyclic_input_validation(
    left: tuple[int, ...],
    right: tuple[int, ...],
    modulus: int,
    match: str,
) -> None:
    with pytest.raises(InputValidationError, match=match):
        negacyclic_multiply(left, right, modulus=modulus)


def test_negacyclic_resource_limits() -> None:
    with pytest.raises(ResourceLimitError, match="modulus"):
        negacyclic_multiply((1,), (1,), modulus=MAX_EDUCATIONAL_MODULUS + 1)
    oversized = tuple(1 for _ in range(MAX_RING_DEGREE + 1))
    with pytest.raises(ResourceLimitError, match="degree bound"):
        negacyclic_multiply(oversized, oversized, modulus=17)


def test_toy_lwe_sample() -> None:
    result = toy_lwe_sample(
        ((1, 2), (3, 4)),
        (5, 6),
        (1, -1),
        modulus=17,
    )
    assert result.matrix == ((1, 2), (3, 4))
    assert result.secret == (5, 6)
    assert result.error == (1, -1)
    assert result.output == ((1 * 5 + 2 * 6 + 1) % 17, (3 * 5 + 4 * 6 - 1) % 17)
    assert result.rows[0].dot_product == 17
    assert result.rows[0].value == 1


def test_toy_lwe_validation_and_limits() -> None:
    with pytest.raises(InputValidationError, match="must not be empty"):
        toy_lwe_sample((), (), (), modulus=17)
    with pytest.raises(InputValidationError, match="error vector"):
        toy_lwe_sample(((1,),), (1,), (), modulus=17)
    with pytest.raises(InputValidationError, match="matrix row"):
        toy_lwe_sample(((1, 2),), (1,), (0,), modulus=17)
    oversized_matrix = tuple((1,) for _ in range(MAX_TOY_LWE_DIMENSION + 1))
    oversized_error = tuple(0 for _ in oversized_matrix)
    with pytest.raises(ResourceLimitError, match="dimensions"):
        toy_lwe_sample(oversized_matrix, (1,), oversized_error, modulus=17)
    oversized_secret = tuple(1 for _ in range(MAX_TOY_LWE_DIMENSION + 1))
    with pytest.raises(ResourceLimitError, match="dimensions"):
        toy_lwe_sample((oversized_secret,), oversized_secret, (0,), modulus=17)
