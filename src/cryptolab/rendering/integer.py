"""Presentation objects for integer arithmetic commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.mathematics.integers import (
    DivisorKind,
    EuclideanAlgorithmResult,
    EuclideanDivisionResult,
    ExtendedGCDResult,
    FactorizationResult,
    PrimeTestResult,
)
from cryptolab.rendering.common import dataclass_to_dict


@dataclass(frozen=True, slots=True)
class DivisionView:
    """Render a Euclidean-division result."""

    result: EuclideanDivisionResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(
            f"[bold]{self.result.dividend} = {self.result.divisor}"
            f"({self.result.quotient}) + {self.result.remainder}[/bold]"
        )
        if explain:
            console.print(
                f"Remainder condition: 0 <= {self.result.remainder} < {abs(self.result.divisor)}"
            )
            console.print("Implementation category: educational")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "integer.divide",
            "implementation": "educational",
            "inputs": {
                "dividend": self.result.dividend,
                "divisor": self.result.divisor,
            },
            "result": {
                "quotient": self.result.quotient,
                "remainder": self.result.remainder,
                "identity_holds": self.result.identity_holds,
                "remainder_bound_holds": self.result.remainder_bound_holds,
            },
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            (
                f"{self.result.dividend} = {self.result.divisor}"
                f"\\left({self.result.quotient}\\right) + {self.result.remainder}"
            ),
            f"0 \\le {self.result.remainder} < {abs(self.result.divisor)}",
        ]
        if explain:
            lines.append(r"\text{Implementation category: educational}")
        return "\\\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class BooleanView:
    """Render a Boolean mathematical result."""

    command: str
    label: str
    value: bool
    inputs: dict[str, int]

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"{self.label}: [bold]{str(self.value).lower()}[/bold]")
        if explain:
            console.print("Implementation category: educational")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": self.command,
            "implementation": "educational",
            "inputs": self.inputs,
            "result": {"value": self.value},
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        value = r"\mathrm{true}" if self.value else r"\mathrm{false}"
        return rf"\text{{{self.label}}} = {value}"


@dataclass(frozen=True, slots=True)
class DivisorsView:
    """Render divisor enumeration."""

    n: int
    kind: DivisorKind
    values: tuple[int, ...]

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Divisors ({self.kind.value}) of {self.n}:")
        console.print(" ".join(str(value) for value in self.values))
        if explain:
            console.print(f"Count: {len(self.values)}")
            console.print("Implementation category: educational")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "integer.divisors",
            "implementation": "educational",
            "inputs": {"n": self.n, "kind": self.kind.value},
            "result": {"divisors": list(self.values), "count": len(self.values)},
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        body = ", ".join(str(value) for value in self.values)
        return (
            rf"\operatorname{{Div}}_{{\mathrm{{{self.kind.value}}}}}({self.n}) "
            rf"= \{{{body}\}}"
        )


@dataclass(frozen=True, slots=True)
class ScalarView:
    """Render a scalar binary integer operation."""

    command: str
    label: str
    a: int
    b: int
    value: int

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"{self.label}({self.a}, {self.b}) = [bold]{self.value}[/bold]")
        if explain:
            console.print("Implementation category: educational")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": self.command,
            "implementation": "educational",
            "inputs": {"a": self.a, "b": self.b},
            "result": {"value": self.value},
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return rf"\operatorname{{{self.label.lower()}}}({self.a}, {self.b}) = {self.value}"


@dataclass(frozen=True, slots=True)
class EuclideanAlgorithmView:
    """Render a Euclidean-algorithm result and optional trace."""

    result: EuclideanAlgorithmResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"gcd({self.result.a}, {self.result.b}) = [bold]{self.result.gcd}[/bold]")
        if explain:
            table = Table("Dividend", "Divisor", "Quotient", "Remainder")
            for step in self.result.steps:
                table.add_row(
                    str(step.dividend),
                    str(step.divisor),
                    str(step.quotient),
                    str(step.remainder),
                )
            console.print(table)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "integer.euclid",
            "implementation": "educational",
            "inputs": {"a": self.result.a, "b": self.result.b},
            "result": {"gcd": self.result.gcd},
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [rf"\gcd({self.result.a}, {self.result.b}) = {self.result.gcd}"]
        if explain:
            lines.extend(
                f"{step.dividend} = {step.divisor}({step.quotient}) + {step.remainder}"
                for step in self.result.steps
            )
        return "\\\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class ExtendedGCDView:
    """Render an extended-gcd result and optional trace."""

    result: ExtendedGCDResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"gcd({self.result.a}, {self.result.b}) = [bold]{self.result.gcd}[/bold]")
        console.print(
            f"Bézout identity: {self.result.a}({self.result.x}) + "
            f"{self.result.b}({self.result.y}) = {self.result.gcd}"
        )
        if explain and self.result.steps:
            table = Table("q", "old r", "r", "old x", "x", "old y", "y")
            for step in self.result.steps:
                table.add_row(
                    str(step.quotient),
                    str(step.old_remainder),
                    str(step.remainder),
                    str(step.old_x),
                    str(step.x),
                    str(step.old_y),
                    str(step.y),
                )
            console.print(table)

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "integer.extended-gcd",
            "implementation": "educational",
            "inputs": {"a": self.result.a, "b": self.result.b},
            "result": {
                "gcd": self.result.gcd,
                "x": self.result.x,
                "y": self.result.y,
                "identity_holds": self.result.identity_holds,
            },
            "trace": [dataclass_to_dict(step) for step in self.result.steps] if explain else [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        return (
            rf"\gcd({self.result.a}, {self.result.b}) = {self.result.gcd}\\"
            "\n"
            rf"{self.result.a}({self.result.x}) + {self.result.b}({self.result.y}) "
            rf"= {self.result.gcd}"
        )


@dataclass(frozen=True, slots=True)
class PrimeTestView:
    """Render a primality-classification result."""

    result: PrimeTestResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        classification = "prime" if self.result.is_prime else "not prime"
        console.print(f"{self.result.n} is [bold]{classification}[/bold].")
        if self.result.divisor is not None:
            console.print(f"Non-trivial divisor found: {self.result.divisor}")
        if explain:
            console.print(f"Tested candidates: {self.result.tested_candidates}")
            console.print("Method: deterministic educational trial division")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "integer.prime-test",
            "implementation": "educational",
            "inputs": {"n": self.result.n},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        relation = r"\in\mathbb{P}" if self.result.is_prime else r"\notin\mathbb{P}"
        return rf"{self.result.n} {relation}"


@dataclass(frozen=True, slots=True)
class FactorizationView:
    """Render a canonical prime factorization."""

    result: FactorizationResult

    def _expression(self) -> str:
        factors = [
            str(item.prime) if item.exponent == 1 else f"{item.prime}^{item.exponent}"
            for item in self.result.factors
        ]
        if self.result.sign < 0:
            factors.insert(0, "-1")
        return " * ".join(factors) if factors else str(self.result.sign)

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"{self.result.n} = [bold]{self._expression()}[/bold]")
        if explain:
            console.print(f"Reconstructed value: {self.result.reconstructed}")
            console.print("Method: deterministic educational trial division")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "integer.factor",
            "implementation": "educational",
            "inputs": {"n": self.result.n},
            "result": {
                "sign": self.result.sign,
                "factors": [dataclass_to_dict(item) for item in self.result.factors],
                "reconstructed": self.result.reconstructed,
            },
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        del explain
        pieces: list[str] = []
        if self.result.sign < 0:
            pieces.append("-1")
        pieces.extend(
            str(item.prime) if item.exponent == 1 else f"{item.prime}^{{{item.exponent}}}"
            for item in self.result.factors
        )
        expression = r" \cdot ".join(pieces) if pieces else str(self.result.sign)
        return rf"{self.result.n} = {expression}"
