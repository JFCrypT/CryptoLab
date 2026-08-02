from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from cryptolab.public_key.elliptic_curve import (
    POINT_AT_INFINITY,
    ECPoint,
    add_points,
    build_elliptic_curve,
    enumerate_curve_points,
    negate_point,
    scalar_multiply,
)

CURVE = build_elliptic_curve(17, 2, 2)
POINTS = (POINT_AT_INFINITY, *enumerate_curve_points(CURVE).finite_points)


@given(st.sampled_from(POINTS), st.sampled_from(POINTS))
def test_point_addition_is_commutative(left: ECPoint, right: ECPoint) -> None:
    assert (
        add_points(CURVE, left, right).trace.result == add_points(CURVE, right, left).trace.result
    )


@given(st.sampled_from(POINTS), st.integers(min_value=-40, max_value=40))
def test_scalar_negation_identity(point: ECPoint, scalar: int) -> None:
    positive = scalar_multiply(CURVE, scalar, point).result
    negative = scalar_multiply(CURVE, -scalar, point).result
    assert negative == negate_point(CURVE, positive).negated
