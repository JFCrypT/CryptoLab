from __future__ import annotations

import pytest

from cryptolab.exceptions import InputValidationError, MathematicalDomainError, ResourceLimitError
from cryptolab.public_key.elliptic_curve import (
    POINT_AT_INFINITY,
    ECPoint,
    add_points,
    build_elliptic_curve,
    enumerate_curve_points,
    is_point_on_curve,
    negate_point,
    normalize_point,
    parse_point_token,
    point_order,
    point_to_token,
    scalar_multiply,
)


def test_curve_inspection_and_point_tokens() -> None:
    curve = build_elliptic_curve(17, 2, 2)
    result = enumerate_curve_points(curve)
    assert curve.nonsingularity_value == 4
    assert result.group_order == 19
    assert len(result.finite_points) == 18
    assert ECPoint(5, 1) in result.finite_points
    assert parse_point_token("5:1") == ECPoint(5, 1)
    assert parse_point_token("INFINITY") == POINT_AT_INFINITY
    assert point_to_token(ECPoint(5, 1)) == "5:1"
    assert point_to_token(POINT_AT_INFINITY) == "infinity"


def test_curve_and_point_validation() -> None:
    with pytest.raises(MathematicalDomainError, match="p >= 5"):
        build_elliptic_curve(3, 1, 1)
    with pytest.raises(ResourceLimitError, match="at most 257"):
        build_elliptic_curve(263, 1, 1)
    with pytest.raises(MathematicalDomainError, match="must be prime"):
        build_elliptic_curve(15, 1, 1)
    with pytest.raises(MathematicalDomainError, match="singular"):
        build_elliptic_curve(17, 0, 0)
    with pytest.raises(InputValidationError, match="x:y"):
        parse_point_token("5")
    with pytest.raises(InputValidationError, match="integers"):
        parse_point_token("x:y")

    curve = build_elliptic_curve(17, 2, 2)
    assert is_point_on_curve(curve, POINT_AT_INFINITY)
    assert is_point_on_curve(curve, ECPoint(5, 1))
    assert not is_point_on_curve(curve, ECPoint(5, 2))
    assert normalize_point(curve, ECPoint(22, 18)) == ECPoint(5, 1)
    with pytest.raises(MathematicalDomainError, match="not on"):
        normalize_point(curve, ECPoint(5, 2))
    with pytest.raises(InputValidationError, match="both coordinates"):
        normalize_point(curve, ECPoint(5, None))


def test_negation_addition_doubling_and_identity() -> None:
    curve = build_elliptic_curve(17, 2, 2)
    point = ECPoint(5, 1)
    inverse = negate_point(curve, point)
    assert inverse.negated == ECPoint(5, 16)
    assert negate_point(curve, POINT_AT_INFINITY).negated == POINT_AT_INFINITY

    doubled = add_points(curve, point, point)
    assert doubled.trace.operation == "doubling"
    assert doubled.trace.numerator == 9
    assert doubled.trace.denominator == 2
    assert doubled.trace.denominator_inverse == 9
    assert doubled.trace.slope == 13
    assert doubled.trace.result == ECPoint(6, 3)

    added = add_points(curve, point, ECPoint(6, 3))
    assert added.trace.operation == "addition"
    assert added.trace.result == ECPoint(10, 6)

    assert add_points(curve, POINT_AT_INFINITY, point).trace.result == point
    assert add_points(curve, point, POINT_AT_INFINITY).trace.result == point
    inverse_sum = add_points(curve, point, inverse.negated)
    assert inverse_sum.trace.operation == "inverse-pair"
    assert inverse_sum.trace.result == POINT_AT_INFINITY

    vertical_curve = build_elliptic_curve(17, 1, 0)
    vertical = ECPoint(0, 0)
    tangent = add_points(vertical_curve, vertical, vertical)
    assert tangent.trace.operation == "vertical-tangent"
    assert tangent.trace.result == POINT_AT_INFINITY


def test_scalar_multiplication_and_point_order() -> None:
    curve = build_elliptic_curve(17, 2, 2)
    point = ECPoint(5, 1)
    assert scalar_multiply(curve, 0, point).result == POINT_AT_INFINITY
    assert scalar_multiply(curve, 1, point).result == point
    assert scalar_multiply(curve, 2, point).result == ECPoint(6, 3)
    assert scalar_multiply(curve, 3, point).result == ECPoint(10, 6)
    assert scalar_multiply(curve, -1, point).result == ECPoint(5, 16)
    assert scalar_multiply(curve, 19, point).result == POINT_AT_INFINITY
    with pytest.raises(ResourceLimitError, match="scalar magnitude"):
        scalar_multiply(curve, 1_000_001, point)

    order = point_order(curve, point)
    assert order.order == 19
    assert order.curve_group_order == 19
    assert order.divides_group_order
    assert order.subgroup[-1] == POINT_AT_INFINITY
    identity_order = point_order(curve, POINT_AT_INFINITY)
    assert identity_order.order == 1
    assert identity_order.subgroup == (POINT_AT_INFINITY,)
