from __future__ import annotations

from rich.console import Console

from cryptolab.mathematics.modular import (
    Congruence,
    generalized_crt,
    modular_add,
    modular_inverse,
    modular_power,
    solve_linear_congruence,
    units,
    zero_divisors,
)
from cryptolab.rendering.modular import (
    CRTView,
    LinearCongruenceView,
    ModularInverseView,
    ModularPowerView,
    ModularScalarView,
    ResidueCollectionView,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_scalar_view_all_formats() -> None:
    view = ModularScalarView.from_result(
        command="modular.add",
        label="add",
        inputs={"a": 14, "b": 20, "modulus": 9},
        result=modular_add(14, 20, 9),
    )
    assert "Canonical range" in render_text(view)
    assert view.render_json(explain=True)["result"]["value"] == 7
    assert "pmod" in view.render_latex(explain=False)


def test_power_view_all_formats() -> None:
    view = ModularPowerView(modular_power(14, 15, 29))
    assert "Squared base" in render_text(view)
    assert view.render_json(explain=True)["trace"]
    assert "square-and-multiply" in view.render_latex(explain=True)
    assert view.render_json(explain=False)["trace"] == []


def test_inverse_view_all_formats() -> None:
    invertible = ModularInverseView(modular_inverse(13, 200))
    assert "Inverse" in render_text(invertible)
    assert invertible.render_json(explain=True)["result"]["inverse"] == 77
    assert "^{-1}" in invertible.render_latex(explain=False)

    noninvertible = ModularInverseView(modular_inverse(54, 200))
    assert "no multiplicative inverse" in render_text(noninvertible)
    assert noninvertible.render_json(explain=False)["result"]["exists"] is False
    assert "neq 1" in noninvertible.render_latex(explain=False)


def test_residue_collection_view_all_formats() -> None:
    unit_view = ResidueCollectionView(units(15))
    assert "Count: 8" in render_text(unit_view)
    assert unit_view.render_json(explain=True)["result"]["count"] == 8
    assert "times" in unit_view.render_latex(explain=False)

    zero_view = ResidueCollectionView(zero_divisors(11))
    assert "(none)" in render_text(zero_view, explain=False)
    assert zero_view.render_json(explain=False)["result"]["values"] == []
    assert "ZD" in zero_view.render_latex(explain=False)


def test_linear_congruence_view_all_formats() -> None:
    solvable = LinearCongruenceView(solve_linear_congruence(15, 30, 55))
    assert "Canonical solutions" in render_text(solvable)
    assert solvable.render_json(explain=True)["trace"]
    assert "x \\in" in solvable.render_latex(explain=True)

    unsolvable = LinearCongruenceView(solve_linear_congruence(9, 2, 36))
    assert "No solutions" in render_text(unsolvable)
    assert unsolvable.render_json(explain=True)["trace"] == []
    assert "No solutions" in unsolvable.render_latex(explain=False)


def test_crt_view_all_formats() -> None:
    solvable_result = generalized_crt((Congruence(5, 7), Congruence(0, 6), Congruence(-1, 5)))
    solvable = CRTView(solvable_result)
    assert "Combined solution" in render_text(solvable)
    assert solvable.render_json(explain=True)["trace"]
    assert "Generalized" in solvable.render_latex(explain=True)

    incompatible = CRTView(generalized_crt((Congruence(1, 4), Congruence(2, 6))))
    assert "incompatible" in render_text(incompatible)
    assert incompatible.render_json(explain=False)["result"]["solvable"] is False
    assert "Incompatible" in incompatible.render_latex(explain=False)
