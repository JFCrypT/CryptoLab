"""Presentation objects for modular arithmetic commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.mathematics.modular import (
    CRTResult,
    LinearCongruenceResult,
    ModularInverseResult,
    ModularPowerResult,
    ModularScalarResult,
    ResidueCollectionResult,
)
from cryptolab.rendering.common import dataclass_to_dict


@dataclass(frozen=True, slots=True)
class ModularScalarView:
    """Render a scalar modular result."""

    command: str
    label: str
    inputs: dict[str, int]
    modulus: int
    value: int

    @classmethod
    def from_result(
        cls,
        *,
        command: str,
        label: str,
        inputs: dict[str, int],
        result: ModularScalarResult,
    ) -> ModularScalarView:
        """Create a view from a domain-level scalar result."""

        return cls(command, label, inputs, result.modulus, result.value)

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"{self.label} modulo {self.modulus} = [bold]{self.value}[/bold]")
        if explain:
            console.print(f"Canonical range: 0 <= r < {self.modulus}")
            console.print("Implementation category: educational")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": self.command,
            "implementation": "educational",
            "inputs": self.inputs,
            "result": {"value": self.value, "modulus": self.modulus},
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"\operatorname{{{self.label}}}(\cdots) \equiv {self.value} \pmod{{{self.modulus}}}"


@dataclass(frozen=True, slots=True)
class ModularPowerView:
    """Render fast modular exponentiation and its optional trace."""

    result: ModularPowerResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(
            f"{self.result.base}^{self.result.exponent} mod {self.result.modulus} = "
            f"[bold]{self.result.value}[/bold]"
        )
        if explain:
            table = Table("Exponent", "Bit", "Accumulator", "Squared base")
            for step in self.result.steps:
                table.add_row(
                    str(step.exponent),
                    str(step.bit),
                    str(step.accumulator),
                    str(step.base),
                )
            console.print(table)
            console.print("Method: right-to-left square-and-multiply")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "modular.power",
            "implementation": "educational",
            "inputs": {
                "base": self.result.base,
                "exponent": self.result.exponent,
                "modulus": self.result.modulus,
            },
            "result": {"value": self.result.value},
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"{self.result.base}^{{{self.result.exponent}}} \equiv "
            rf"{self.result.value} \pmod{{{self.result.modulus}}}"
        ]
        if explain:
            lines.append(r"\text{Method: right-to-left square-and-multiply}")
        return "\\\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class ModularInverseView:
    """Render a modular inverse or a valid non-existence result."""

    result: ModularInverseResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        if self.result.exists:
            console.print(
                f"Inverse of {self.result.value} modulo {self.result.modulus}: "
                f"[bold]{self.result.inverse}[/bold]"
            )
        else:
            console.print(
                f"{self.result.value} has [bold]no multiplicative inverse[/bold] "
                f"modulo {self.result.modulus}."
            )
        if explain:
            console.print(f"gcd({self.result.value}, {self.result.modulus}) = {self.result.gcd}")
            console.print(f"Bézout coefficient for the value: {self.result.bezout_x}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "modular.inverse",
            "implementation": "educational",
            "inputs": {"value": self.result.value, "modulus": self.result.modulus},
            "result": {
                "exists": self.result.exists,
                "inverse": self.result.inverse,
                "gcd": self.result.gcd,
            },
            "trace": ([{"bezout_x": self.result.bezout_x}] if explain else []),
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        if self.result.exists:
            return (
                rf"{self.result.value}^{{-1}} \equiv {self.result.inverse} "
                rf"\pmod{{{self.result.modulus}}}"
            )
        return (
            rf"\gcd({self.result.value},{self.result.modulus}) = {self.result.gcd} "
            r"\neq 1"
        )


@dataclass(frozen=True, slots=True)
class ResidueCollectionView:
    """Render units or non-zero zero divisors modulo n."""

    result: ResidueCollectionResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        label = "Units" if self.result.kind == "units" else "Non-zero zero divisors"
        console.print(f"{label} modulo {self.result.modulus}:")
        console.print(" ".join(str(value) for value in self.result.values) or "(none)")
        if explain:
            console.print(f"Count: {len(self.result.values)}")
            console.print("Canonical representatives exclude 0 from zero-divisor listings.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": f"modular.{self.result.kind}",
            "implementation": "educational",
            "inputs": {"modulus": self.result.modulus},
            "result": {
                "values": list(self.result.values),
                "count": len(self.result.values),
            },
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        body = ", ".join(str(value) for value in self.result.values)
        if self.result.kind == "units":
            symbol = rf"\mathbb{{Z}}_{{{self.result.modulus}}}^{{\times}}"
        else:
            symbol = rf"ZD^*(\mathbb{{Z}}_{{{self.result.modulus}}})"
        return rf"{symbol} = \{{{body}\}}"


@dataclass(frozen=True, slots=True)
class LinearCongruenceView:
    """Render every canonical solution of a linear congruence."""

    result: LinearCongruenceResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(
            f"Equation: [bold]{self.result.a}x ≡ {self.result.b} (mod {self.result.modulus})[/bold]"
        )
        if not self.result.solvable:
            console.print("No solutions.")
        else:
            console.print(
                "Canonical solutions: " + ", ".join(str(value) for value in self.result.solutions)
            )
        if explain:
            console.print(f"gcd(a, n) = {self.result.gcd}")
            if self.result.solvable:
                console.print(
                    "Reduced congruence: "
                    f"{self.result.reduced_a}x ≡ {self.result.reduced_b} "
                    f"(mod {self.result.reduced_modulus})"
                )
                console.print(f"Base solution: {self.result.base_solution}")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        trace: list[dict[str, int | None]] = []
        if explain and self.result.solvable:
            trace.append(
                {
                    "reduced_a": self.result.reduced_a,
                    "reduced_b": self.result.reduced_b,
                    "reduced_modulus": self.result.reduced_modulus,
                    "base_solution": self.result.base_solution,
                }
            )
        return {
            "schema_version": "1.0",
            "command": "modular.solve-linear",
            "implementation": "educational",
            "inputs": {
                "a": self.result.a,
                "b": self.result.b,
                "modulus": self.result.modulus,
            },
            "result": {
                "solvable": self.result.solvable,
                "gcd": self.result.gcd,
                "solutions": list(self.result.solutions),
            },
            "trace": trace,
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"{self.result.a}x \equiv {self.result.b} "
            rf"\pmod{{{self.result.modulus}}}"
        ]
        if self.result.solvable:
            body = ", ".join(str(value) for value in self.result.solutions)
            lines.append(rf"x \in \{{{body}\}} \pmod{{{self.result.modulus}}}")
        else:
            lines.append(r"\text{No solutions.}")
        if explain:
            lines.append(rf"\gcd({self.result.a},{self.result.modulus})={self.result.gcd}")
        return "\\\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class CRTView:
    """Render a generalized Chinese Remainder Theorem result."""

    result: CRTResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        for congruence in self.result.congruences:
            console.print(f"x ≡ {congruence.residue} (mod {congruence.modulus})")
        if self.result.solvable:
            console.print(
                f"Combined solution: [bold]x ≡ {self.result.residue} "
                f"(mod {self.result.modulus})[/bold]"
            )
        else:
            console.print("The congruence system is incompatible.")
        if explain and self.result.steps:
            table = Table("Left", "Right", "gcd", "Difference", "Compatible", "Merged")
            for step in self.result.steps:
                merged = (
                    f"{step.merged_residue} mod {step.merged_modulus}" if step.compatible else "—"
                )
                table.add_row(
                    f"{step.left_residue} mod {step.left_modulus}",
                    f"{step.right_residue} mod {step.right_modulus}",
                    str(step.gcd),
                    str(step.difference),
                    str(step.compatible),
                    merged,
                )
            console.print(table)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "modular.crt",
            "implementation": "educational",
            "inputs": {
                "congruences": [dataclass_to_dict(item) for item in self.result.congruences]
            },
            "result": {
                "solvable": self.result.solvable,
                "residue": self.result.residue,
                "modulus": self.result.modulus,
            },
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"x \equiv {item.residue} \pmod{{{item.modulus}}}" for item in self.result.congruences
        ]
        if self.result.solvable:
            lines.append(rf"x \equiv {self.result.residue} \pmod{{{self.result.modulus}}}")
        else:
            lines.append(r"\text{Incompatible system.}")
        if explain:
            lines.append(r"\text{Generalized Chinese Remainder Theorem}")
        return "\\\\\n".join(lines)
