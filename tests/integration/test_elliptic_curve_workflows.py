from __future__ import annotations

from cryptolab.public_key.elliptic_curve import (
    POINT_AT_INFINITY,
    ECPoint,
    add_points,
    build_elliptic_curve,
    enumerate_curve_points,
    point_order,
    scalar_multiply,
)


def test_curve_group_workflow() -> None:
    curve = build_elliptic_curve(17, 2, 2)
    inspection = enumerate_curve_points(curve)
    generator = ECPoint(5, 1)
    order = point_order(curve, generator)
    assert inspection.group_order == 19
    assert order.order == inspection.group_order
    assert scalar_multiply(curve, order.order, generator).result == POINT_AT_INFINITY
    for scalar in range(order.order):
        result = scalar_multiply(curve, scalar, generator).result
        assert result in order.subgroup or result == POINT_AT_INFINITY


def test_curve_addition_matches_scalar_multiplication() -> None:
    curve = build_elliptic_curve(17, 2, 2)
    point = ECPoint(5, 1)
    doubled = add_points(curve, point, point).trace.result
    tripled = add_points(curve, doubled, point).trace.result
    assert doubled == scalar_multiply(curve, 2, point).result
    assert tripled == scalar_multiply(curve, 3, point).result
