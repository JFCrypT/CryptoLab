from __future__ import annotations

from rich.console import Console

from cryptolab.mathematics.integers import (
    DivisorKind,
    divisors,
    euclidean_algorithm,
    euclidean_division,
    extended_gcd,
    factor_integer,
    is_prime,
)
from cryptolab.rendering.integer import (
    BooleanView,
    DivisionView,
    DivisorsView,
    EuclideanAlgorithmView,
    ExtendedGCDView,
    FactorizationView,
    PrimeTestView,
    ScalarView,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_division_view_all_formats() -> None:
    view = DivisionView(euclidean_division(-17, 5))
    assert "Remainder condition" in render_text(view)
    assert view.render_json(explain=True)["result"]["quotient"] == -4
    assert "\\left(-4\\right)" in view.render_latex(explain=True)


def test_boolean_view_all_formats() -> None:
    view = BooleanView("integer.divides", "5 divides 35", True, {"divisor": 5, "dividend": 35})
    assert "true" in render_text(view)
    assert view.render_json(explain=False)["result"]["value"] is True
    assert "mathrm{true}" in view.render_latex(explain=False)


def test_divisors_view_all_formats() -> None:
    values = divisors(12, DivisorKind.ALL)
    view = DivisorsView(12, DivisorKind.ALL, values)
    assert "Count: 12" in render_text(view)
    assert view.render_json(explain=True)["result"]["count"] == 12
    assert "operatorname{Div}" in view.render_latex(explain=True)


def test_scalar_view_all_formats() -> None:
    view = ScalarView("integer.gcd", "gcd", 12, 18, 6)
    assert "gcd(12, 18)" in render_text(view)
    assert view.render_json(explain=True)["result"]["value"] == 6
    assert "operatorname{gcd}" in view.render_latex(explain=True)


def test_euclidean_algorithm_view_all_formats() -> None:
    view = EuclideanAlgorithmView(euclidean_algorithm(250, 110))
    assert "Dividend" in render_text(view)
    assert len(view.render_json(explain=True)["trace"]) == 4
    assert "250 = 110(2) + 30" in view.render_latex(explain=True)
    assert view.render_json(explain=False)["trace"] == []


def test_extended_gcd_view_all_formats() -> None:
    view = ExtendedGCDView(extended_gcd(250, 110))
    assert "Bézout identity" in render_text(view)
    assert view.render_json(explain=True)["result"]["identity_holds"] is True
    assert "\\gcd" in view.render_latex(explain=True)


def test_extended_gcd_view_without_steps() -> None:
    view = ExtendedGCDView(extended_gcd(0, 0))
    assert "Bézout identity" in render_text(view)


def test_prime_view_all_formats() -> None:
    composite = PrimeTestView(is_prime(221))
    assert "Non-trivial divisor" in render_text(composite)
    assert composite.render_json(explain=True)["result"]["divisor"] == 13
    assert "notin" in composite.render_latex(explain=True)

    prime = PrimeTestView(is_prime(97))
    assert "prime" in render_text(prime, explain=False)
    assert "in\\mathbb" in prime.render_latex(explain=False)


def test_factorization_view_all_formats() -> None:
    view = FactorizationView(factor_integer(-360))
    assert "-1 * 2^3 * 3^2 * 5" in render_text(view)
    assert view.render_json(explain=True)["result"]["reconstructed"] == -360
    assert "\\cdot" in view.render_latex(explain=True)

    unit = FactorizationView(factor_integer(1))
    assert "1 = 1" in render_text(unit, explain=False)
    assert unit.render_latex(explain=False) == "1 = 1"
