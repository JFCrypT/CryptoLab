from __future__ import annotations

from rich.console import Console

from cryptolab.mathematics.diophantine import solve_diophantine
from cryptolab.rendering.diophantine import (
    DiophantineSolutionView,
    DiophantineVerificationView,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_parametric_solution_view_all_formats() -> None:
    view = DiophantineSolutionView(solve_diophantine(2, -5, 1))
    text = render_text(view)
    assert "General solution" in text
    payload = view.render_json(explain=True)
    assert payload["result"]["solvable"] is True
    assert payload["trace"]
    assert "mathbb{Z}" in view.render_latex(explain=True)


def test_unsolvable_solution_view_all_formats() -> None:
    view = DiophantineSolutionView(solve_diophantine(6, -9, 8))
    assert "No integer solutions" in render_text(view)
    payload = view.render_json(explain=False)
    assert payload["result"]["kind"] == "none"
    assert payload["trace"] == []
    assert "No integer solutions" in view.render_latex(explain=False)


def test_all_pairs_solution_view_all_formats() -> None:
    view = DiophantineSolutionView(solve_diophantine(0, 0, 0))
    assert "Every integer pair" in render_text(view)
    assert view.render_json(explain=True)["result"]["kind"] == "all-integer-pairs"
    assert "mathbb{Z}^2" in view.render_latex(explain=False)


def test_verification_view_all_formats() -> None:
    valid = DiophantineVerificationView(2, -5, 1, 3, 1, True)
    assert "is a solution" in render_text(valid)
    assert valid.render_json(explain=True)["result"]["valid"] is True
    assert "=" in valid.render_latex(explain=True)

    invalid = DiophantineVerificationView(2, -5, 1, 0, 0, False)
    assert "is not" in render_text(invalid, explain=False)
    assert invalid.render_json(explain=False)["trace"] == []
    assert "neq" in invalid.render_latex(explain=False)
