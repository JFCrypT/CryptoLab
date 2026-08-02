"""Presentation objects for educational elliptic-curve arithmetic."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.public_key.elliptic_curve import (
    ECAdditionResult,
    ECCurveInspectionResult,
    ECNegationResult,
    ECPointOrderResult,
    ECScalarMultiplicationResult,
    point_to_token,
)
from cryptolab.rendering.common import dataclass_to_dict

EDUCATIONAL_EC_WARNING = "These small elliptic-curve parameters are educational and are not secure."


@dataclass(frozen=True, slots=True)
class ECCurveInspectionView:
    """Render a non-singular small curve and all of its points."""

    result: ECCurveInspectionResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        curve = self.result.curve
        table = Table("Property", "Value")
        table.add_row("Field", f"F_{curve.prime}")
        table.add_row("Equation", f"y^2 = x^3 + {curve.a}x + {curve.b} mod {curve.prime}")
        table.add_row("4a^3 + 27b^2 mod p", str(curve.nonsingularity_value))
        table.add_row("Non-singular", "True")
        table.add_row("Affine points", str(len(self.result.finite_points)))
        table.add_row("Group order including infinity", str(self.result.group_order))
        console.print(table)
        points = Table("Index", "Point")
        points.add_row("0", "infinity")
        for index, point in enumerate(self.result.finite_points, start=1):
            points.add_row(str(index), point_to_token(point))
        console.print(points)
        if explain:
            console.print("The point at infinity is the additive identity of the curve group.")
            console.print("Non-singularity requires 4a^3 + 27b^2 not congruent to zero modulo p.")
            console.print(f"Warning: {EDUCATIONAL_EC_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key ecc inspect",
            "implementation": "educational",
            "inputs": {
                "prime": self.result.curve.prime,
                "a": self.result.curve.a,
                "b": self.result.curve.b,
            },
            "result": {
                "curve": dataclass_to_dict(self.result.curve),
                "finite_points": [dataclass_to_dict(point) for point in self.result.finite_points],
                "group_order": self.result.group_order,
                "point_at_infinity_included": True,
            },
            "trace": [],
            "warnings": [EDUCATIONAL_EC_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        curve = self.result.curve
        lines = [
            rf"E/\mathbb{{F}}_{{{curve.prime}}}: y^2=x^3+{curve.a}x+{curve.b}",
            rf"4a^3+27b^2\equiv {curve.nonsingularity_value}\not\equiv 0"
            rf"\pmod{{{curve.prime}}}",
            rf"\#E(\mathbb{{F}}_{{{curve.prime}}})={self.result.group_order}",
        ]
        if explain:
            lines.append(r"\mathcal{O}\text{ is the additive identity}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class ECNegationView:
    """Render point negation."""

    result: ECNegationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(
            f"-{point_to_token(self.result.point)} = {point_to_token(self.result.negated)}"
        )
        if explain:
            console.print("For a finite point (x, y), its inverse is (x, -y mod p).")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.ecc.negate",
            "implementation": "educational",
            "inputs": {"point": dataclass_to_dict(self.result.point)},
            "result": {"negated": dataclass_to_dict(self.result.negated)},
            "trace": [],
            "warnings": [EDUCATIONAL_EC_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"-{point_to_token(self.result.point)}={point_to_token(self.result.negated)}"


@dataclass(frozen=True, slots=True)
class ECAdditionView:
    """Render point addition or doubling."""

    result: ECAdditionResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        trace = self.result.trace
        console.print(
            f"{point_to_token(self.result.left)} + {point_to_token(self.result.right)} = "
            f"{point_to_token(trace.result)}"
        )
        if explain:
            table = Table("Property", "Value")
            table.add_row("Operation", trace.operation)
            table.add_row("Numerator", "—" if trace.numerator is None else str(trace.numerator))
            table.add_row(
                "Denominator", "—" if trace.denominator is None else str(trace.denominator)
            )
            table.add_row(
                "Denominator inverse",
                "—" if trace.denominator_inverse is None else str(trace.denominator_inverse),
            )
            table.add_row("Slope", "—" if trace.slope is None else str(trace.slope))
            console.print(table)
            console.print(f"Warning: {EDUCATIONAL_EC_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.ecc.add",
            "implementation": "educational",
            "inputs": {
                "left": dataclass_to_dict(self.result.left),
                "right": dataclass_to_dict(self.result.right),
            },
            "result": {
                "operation": self.result.trace.operation,
                "point": dataclass_to_dict(self.result.trace.result),
            },
            "trace": [dataclass_to_dict(self.result.trace)] if explain else [],
            "warnings": [EDUCATIONAL_EC_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"{point_to_token(self.result.left)}+{point_to_token(self.result.right)}="
            rf"{point_to_token(self.result.trace.result)}"
        ]
        if explain and self.result.trace.slope is not None:
            lines.append(rf"\lambda={self.result.trace.slope}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class ECScalarMultiplicationView:
    """Render scalar multiplication and double-and-add states."""

    result: ECScalarMultiplicationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(
            f"{self.result.scalar} * {point_to_token(self.result.point)} = "
            f"{point_to_token(self.result.result)}"
        )
        if explain:
            table = Table(
                "Remaining scalar",
                "Bit",
                "Accumulator before",
                "Addend before",
                "Accumulator after",
                "Doubled addend",
            )
            for step in self.result.steps:
                table.add_row(
                    str(step.remaining_scalar),
                    str(step.bit),
                    point_to_token(step.accumulator_before),
                    point_to_token(step.addend_before),
                    point_to_token(step.accumulator_after),
                    point_to_token(step.addend_after),
                )
            console.print(table)
            console.print("Method: right-to-left double-and-add")
            console.print(f"Warning: {EDUCATIONAL_EC_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.ecc.multiply",
            "implementation": "educational",
            "inputs": {
                "scalar": self.result.scalar,
                "point": dataclass_to_dict(self.result.point),
            },
            "result": {"point": dataclass_to_dict(self.result.result)},
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": [EDUCATIONAL_EC_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"{self.result.scalar}\,{point_to_token(self.result.point)}="
            rf"{point_to_token(self.result.result)}"
        ]
        if explain:
            lines.append(r"\text{right-to-left double-and-add}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class ECPointOrderView:
    """Render point order and generated subgroup."""

    result: ECPointOrderResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Point: {point_to_token(self.result.point)}")
        console.print(f"Point order: {self.result.order}")
        console.print(f"Curve group order: {self.result.curve_group_order}")
        console.print(f"Order divides group order: {self.result.divides_group_order}")
        table = Table("Multiple", "Point")
        for multiple, point in enumerate(self.result.subgroup, start=1):
            table.add_row(str(multiple), point_to_token(point))
        console.print(table)
        if explain:
            console.print(
                "The elliptic-curve discrete logarithm problem asks for k given P and Q = kP."
            )
            console.print(f"Warning: {EDUCATIONAL_EC_WARNING}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "public-key.ecc.subgroup",
            "implementation": "educational",
            "inputs": {"point": dataclass_to_dict(self.result.point)},
            "result": {
                "order": self.result.order,
                "curve_group_order": self.result.curve_group_order,
                "divides_group_order": self.result.divides_group_order,
                "subgroup": [dataclass_to_dict(point) for point in self.result.subgroup],
            },
            "trace": [],
            "warnings": [EDUCATIONAL_EC_WARNING],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"\operatorname{{ord}}({point_to_token(self.result.point)})={self.result.order}",
            rf"{self.result.order}\mid {self.result.curve_group_order}",
        ]
        if explain:
            lines.append(r"Q=kP\text{ defines the educational ECDLP relation}")
        return "\\\n".join(lines)
