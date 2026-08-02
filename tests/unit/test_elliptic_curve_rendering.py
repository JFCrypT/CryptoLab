from __future__ import annotations

from rich.console import Console

from cryptolab.public_key.elliptic_curve import (
    POINT_AT_INFINITY,
    ECPoint,
    add_points,
    build_elliptic_curve,
    enumerate_curve_points,
    negate_point,
    point_order,
    scalar_multiply,
)
from cryptolab.rendering.elliptic_curve import (
    ECAdditionView,
    ECCurveInspectionView,
    ECNegationView,
    ECPointOrderView,
    ECScalarMultiplicationView,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True, width=240)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_curve_inspection_view_all_formats() -> None:
    curve = build_elliptic_curve(17, 2, 2)
    view = ECCurveInspectionView(enumerate_curve_points(curve))
    text = render_text(view)
    assert "Group order including infinity" in text
    assert "5:1" in text
    assert "additive identity" in text
    payload = view.render_json(explain=True)
    assert payload["result"]["group_order"] == 19
    assert len(payload["result"]["finite_points"]) == 18
    assert "#E" in view.render_latex(explain=True)


def test_point_operation_views_all_formats() -> None:
    curve = build_elliptic_curve(17, 2, 2)
    point = ECPoint(5, 1)

    negation = ECNegationView(negate_point(curve, point))
    assert "5:16" in render_text(negation)
    assert negation.render_json(explain=False)["result"]["negated"]["y"] == 16
    assert "5:16" in negation.render_latex(explain=False)

    addition = ECAdditionView(add_points(curve, point, point))
    addition_text = render_text(addition)
    assert "5:1 + 5:1 = 6:3" in addition_text
    assert "doubling" in addition_text
    assert addition.render_json(explain=True)["trace"][0]["slope"] == 13
    assert "lambda" in addition.render_latex(explain=True)

    identity = ECAdditionView(add_points(curve, POINT_AT_INFINITY, point))
    assert "infinity + 5:1 = 5:1" in render_text(identity, explain=False)


def test_scalar_and_subgroup_views_all_formats() -> None:
    curve = build_elliptic_curve(17, 2, 2)
    point = ECPoint(5, 1)
    scalar = ECScalarMultiplicationView(scalar_multiply(curve, 3, point))
    text = render_text(scalar)
    assert "3 * 5:1 = 10:6" in text
    assert "double-and-add" in text
    payload = scalar.render_json(explain=True)
    assert payload["result"]["point"] == {"x": 10, "y": 6}
    assert payload["trace"]
    assert "double-and-add" in scalar.render_latex(explain=True)

    subgroup = ECPointOrderView(point_order(curve, point))
    subgroup_text = render_text(subgroup)
    assert "Point order: 19" in subgroup_text
    assert "discrete logarithm" in subgroup_text
    subgroup_payload = subgroup.render_json(explain=True)
    assert subgroup_payload["result"]["order"] == 19
    assert subgroup_payload["result"]["subgroup"][-1] == {"x": None, "y": None}
    assert "operatorname" in subgroup.render_latex(explain=True)
