"""Presentation objects for linear Diophantine equations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console

from cryptolab.mathematics.diophantine import (
    DiophantineResult,
    DiophantineSolutionKind,
)
from cryptolab.rendering.common import dataclass_to_dict


def _equation_text(a: int, b: int, c: int) -> str:
    operator = "+" if b >= 0 else "-"
    return f"{a}x {operator} {abs(b)}y = {c}"


@dataclass(frozen=True, slots=True)
class DiophantineSolutionView:
    """Render the complete solution classification of ``ax + by = c``."""

    result: DiophantineResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(
            f"Equation: [bold]{_equation_text(self.result.a, self.result.b, self.result.c)}[/bold]"
        )
        if self.result.kind is DiophantineSolutionKind.NONE:
            console.print("No integer solutions.")
        elif self.result.kind is DiophantineSolutionKind.ALL_INTEGER_PAIRS:
            console.print("Every integer pair (x, y) is a solution.")
        else:
            console.print(f"Particular solution: (x0, y0) = ({self.result.x0}, {self.result.y0})")
            console.print(
                f"General solution: x = {self.result.x0} + ({self.result.step_x})t, "
                f"y = {self.result.y0} + ({self.result.step_y})t, t in Z"
            )

        if explain:
            console.print(f"gcd(a, b) = {self.result.gcd}")
            reduced = self.result.reduced
            console.print(
                f"Reduced equivalent equation: {_equation_text(reduced.a, reduced.b, reduced.c)}"
            )
            console.print(f"Reduction scale factor: {self.result.reduced.scale_factor}")
            console.print("Implementation category: educational")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        result: dict[str, Any] = {
            "kind": self.result.kind.value,
            "solvable": self.result.solvable,
            "gcd": self.result.gcd,
            "x0": self.result.x0,
            "y0": self.result.y0,
            "step_x": self.result.step_x,
            "step_y": self.result.step_y,
            "particular_solution_holds": self.result.particular_solution_holds,
        }
        trace = (
            [
                {
                    "reduced_equation": dataclass_to_dict(self.result.reduced),
                    "solvability_criterion": (
                        "gcd(a, b) divides c"
                        if self.result.gcd != 0
                        else "degenerate zero-coefficient equation"
                    ),
                }
            ]
            if explain
            else []
        )
        return {
            "schema_version": "1.0",
            "command": "diophantine.solve",
            "implementation": "educational",
            "inputs": {"a": self.result.a, "b": self.result.b, "c": self.result.c},
            "result": result,
            "trace": trace,
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [_equation_text(self.result.a, self.result.b, self.result.c)]
        if self.result.kind is DiophantineSolutionKind.NONE:
            lines.append(r"\text{No integer solutions.}")
        elif self.result.kind is DiophantineSolutionKind.ALL_INTEGER_PAIRS:
            lines.append(r"(x,y) \in \mathbb{Z}^2")
        else:
            lines.append(
                rf"x = {self.result.x0} + ({self.result.step_x})t,\quad "
                rf"y = {self.result.y0} + ({self.result.step_y})t,\quad "
                r"t \in \mathbb{Z}"
            )
        if explain:
            lines.append(rf"\gcd({self.result.a},{self.result.b}) = {self.result.gcd}")
        return "\\\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class DiophantineVerificationView:
    """Render verification of one candidate integer pair."""

    a: int
    b: int
    c: int
    x: int
    y: int
    valid: bool

    def render_human(self, console: Console, *, explain: bool) -> None:
        status = "is" if self.valid else "is not"
        console.print(f"({self.x}, {self.y}) [bold]{status}[/bold] a solution.")
        if explain:
            left = self.a * self.x + self.b * self.y
            console.print(f"Left-hand side: {self.a}({self.x}) + {self.b}({self.y}) = {left}")
            console.print(f"Right-hand side: {self.c}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "diophantine.verify",
            "implementation": "educational",
            "inputs": {
                "a": self.a,
                "b": self.b,
                "c": self.c,
                "x": self.x,
                "y": self.y,
            },
            "result": {"valid": self.valid},
            "trace": (
                [{"left_hand_side": self.a * self.x + self.b * self.y, "right_hand_side": self.c}]
                if explain
                else []
            ),
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        relation = "=" if self.valid else r"\neq"
        expression = rf"{self.a}({self.x}) + {self.b}({self.y}) {relation} {self.c}"
        if explain:
            return expression + rf"\quad\left({self.a * self.x + self.b * self.y}\right)"
        return expression
