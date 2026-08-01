"""Presentation objects for educational algebraic-structure computations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.mathematics.algebra import (
    ElementOrderResult,
    GeneratedSubgroupResult,
    GeneratorCollectionResult,
    GroupOperation,
    ZnStructureResult,
)
from cryptolab.rendering.common import dataclass_to_dict


def _group_label(operation: GroupOperation, modulus: int) -> str:
    if operation is GroupOperation.ADDITIVE:
        return f"(Z_{modulus}, +)"
    return f"Z_{modulus}^\N{MULTIPLICATION SIGN}"


@dataclass(frozen=True, slots=True)
class ZnStructureView:
    """Render structural properties of Z_n."""

    result: ZnStructureResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"[bold]Algebraic structure of Z_{self.result.modulus}[/bold]")
        table = Table("Property", "Value")
        table.add_row("Prime modulus", str(self.result.is_prime_modulus))
        table.add_row("Additive group order", str(self.result.additive_group_order))
        table.add_row("Unit group order", str(self.result.unit_group_order))
        table.add_row("Additive group cyclic", str(self.result.additive_group_is_cyclic))
        table.add_row("Unit group abelian", str(self.result.unit_group_is_abelian))
        table.add_row(
            "Commutative ring with identity",
            str(self.result.is_commutative_ring_with_identity),
        )
        table.add_row("Integral domain", str(self.result.is_integral_domain))
        table.add_row("Field", str(self.result.is_field))
        console.print(table)
        if explain:
            console.print("Units: " + ", ".join(str(value) for value in self.result.units))
            zero_divisors = ", ".join(str(value) for value in self.result.nonzero_zero_divisors)
            console.print("Non-zero zero divisors: " + (zero_divisors or "(none)"))
            console.print(
                "Z_n is a field and an integral domain exactly when n is prime; "
                "zero is not required to have a multiplicative inverse."
            )

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        properties = {
            "prime_modulus": self.result.is_prime_modulus,
            "additive_group_order": self.result.additive_group_order,
            "unit_group_order": self.result.unit_group_order,
            "additive_group_is_cyclic": self.result.additive_group_is_cyclic,
            "unit_group_is_abelian": self.result.unit_group_is_abelian,
            "is_commutative_ring_with_identity": self.result.is_commutative_ring_with_identity,
            "is_integral_domain": self.result.is_integral_domain,
            "is_field": self.result.is_field,
        }
        trace: list[dict[str, object]] = []
        if explain:
            trace.append(
                {
                    "units": list(self.result.units),
                    "nonzero_zero_divisors": list(self.result.nonzero_zero_divisors),
                }
            )
        return {
            "schema_version": "1.0",
            "command": "algebra.zn",
            "implementation": "educational",
            "inputs": {"modulus": self.result.modulus},
            "result": properties,
            "trace": trace,
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"\mathbb{{Z}}_{{{self.result.modulus}}}\text{{ is a field}} "
            rf"\iff {str(self.result.is_field).lower()}"
        ]
        if explain:
            units = ", ".join(str(value) for value in self.result.units)
            lines.append(rf"\mathbb{{Z}}_{{{self.result.modulus}}}^{{\times}} = \{{{units}\}}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class ElementOrderView:
    """Render an element order and its orbit."""

    result: ElementOrderResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        label = _group_label(self.result.operation, self.result.modulus)
        console.print(
            f"Order of {self.result.normalized_element} in {label}: "
            f"[bold]{self.result.order}[/bold]"
        )
        if explain:
            table = Table("Exponent", "Value")
            for step in self.result.steps:
                table.add_row(str(step.exponent), str(step.value))
            console.print(table)
            console.print(f"Identity: {self.result.identity}")
            console.print(f"Ambient group order: {self.result.ambient_group_order}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "algebra.order",
            "implementation": "educational",
            "inputs": {
                "element": self.result.element,
                "modulus": self.result.modulus,
                "operation": self.result.operation.value,
            },
            "result": {
                "normalized_element": self.result.normalized_element,
                "identity": self.result.identity,
                "ambient_group_order": self.result.ambient_group_order,
                "order": self.result.order,
            },
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        operation = "+" if self.result.operation is GroupOperation.ADDITIVE else r"\times"
        return (
            rf"\operatorname{{ord}}_{{(\mathbb{{Z}}_{{{self.result.modulus}}},{operation})}}"
            rf"({self.result.normalized_element})={self.result.order}"
        )


@dataclass(frozen=True, slots=True)
class GeneratedSubgroupView:
    """Render a generated subgroup."""

    result: GeneratedSubgroupResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        label = _group_label(self.result.operation, self.result.modulus)
        body = ", ".join(str(value) for value in self.result.elements)
        console.print(f"<{self.result.normalized_element}> in {label} = [bold]{{{body}}}[/bold]")
        if explain:
            console.print(f"Subgroup order: {self.result.order}")
            console.print("Elements are listed from the identity through successive powers.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "algebra.subgroup",
            "implementation": "educational",
            "inputs": {
                "element": self.result.element,
                "modulus": self.result.modulus,
                "operation": self.result.operation.value,
            },
            "result": {
                "normalized_element": self.result.normalized_element,
                "order": self.result.order,
                "elements": list(self.result.elements),
            },
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        body = ", ".join(str(value) for value in self.result.elements)
        return rf"\langle {self.result.normalized_element} \rangle = \{{{body}\}}"


@dataclass(frozen=True, slots=True)
class GeneratorCollectionView:
    """Render every generator of a selected finite group."""

    result: GeneratorCollectionResult
    command: str = "algebra.generators"

    def render_human(self, console: Console, *, explain: bool) -> None:
        label = _group_label(self.result.operation, self.result.modulus)
        if self.result.cyclic:
            body = ", ".join(str(value) for value in self.result.generators)
            console.print(f"Generators of {label}: [bold]{body}[/bold]")
        else:
            console.print(f"{label} is not cyclic; it has no group generator.")
        if explain:
            console.print(f"Ambient group order: {self.result.ambient_group_order}")
            console.print(f"Generator count: {len(self.result.generators)}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": self.command,
            "implementation": "educational",
            "inputs": {
                "modulus": self.result.modulus,
                "operation": self.result.operation.value,
            },
            "result": {
                "ambient_group_order": self.result.ambient_group_order,
                "cyclic": self.result.cyclic,
                "generators": list(self.result.generators),
            },
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        body = ", ".join(str(value) for value in self.result.generators)
        return rf"\operatorname{{Gen}} = \{{{body}\}}"
