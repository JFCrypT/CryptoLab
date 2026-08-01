"""Presentation objects for LFSR generation and binary-sequence analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from cryptolab.rendering.common import dataclass_to_dict
from cryptolab.sequences.analysis import SequenceAnalysisResult
from cryptolab.sequences.lfsr import (
    LFSRDiagramResult,
    LFSRGenerationResult,
    LFSRPeriodResult,
)


def _state_text(state: tuple[int, ...]) -> str:
    return "".join(str(bit) for bit in state)


@dataclass(frozen=True, slots=True)
class LFSRGenerationView:
    """Render an LFSR output sequence and optional state table."""

    result: LFSRGenerationResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(self.result.output)
        if explain:
            console.print(f"Polynomial: {self.result.polynomial.canonical}")
            console.print(f"Seed [s_(m-1), ..., s_0]: {_state_text(self.result.seed)}")
            console.print("Convention: Fibonacci LFSR, right shift, output s_0.")
            table = Table("t", "State before", "Output", "Feedback", "State after")
            for transition in self.result.transitions:
                table.add_row(
                    str(transition.time),
                    _state_text(transition.state_before),
                    str(transition.output_bit),
                    str(transition.feedback_bit),
                    _state_text(transition.state_after),
                )
            console.print(table)
            if self.result.trace_truncated:
                console.print("State trace was truncated at the configured row limit.")
            console.print("An LFSR alone is not a cryptographically secure pseudorandom generator.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "sequence.lfsr.generate",
            "implementation": "educational",
            "inputs": {
                "polynomial": self.result.polynomial.canonical,
                "seed": _state_text(self.result.seed),
                "length": self.result.length,
            },
            "result": {
                "output": self.result.output,
                "final_state": _state_text(self.result.final_state),
                "trace_truncated": self.result.trace_truncated,
            },
            "trace": (
                [dataclass_to_dict(transition) for transition in self.result.transitions]
                if explain
                else []
            ),
            "warnings": ["An LFSR alone is not a cryptographically secure PRNG."],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"C(x)={self.result.polynomial.canonical}",
            rf"S_0=\mathtt{{{_state_text(self.result.seed)}}}",
            rf"z=\mathtt{{{self.result.output}}}",
        ]
        if explain:
            lines.append(r"\text{Fibonacci LFSR, right shift, output stage }s_0")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class LFSRPeriodView:
    """Render detected LFSR cycle information."""

    result: LFSRPeriodResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"Period: {self.result.period}")
        if explain:
            console.print(f"Polynomial: {self.result.polynomial.canonical}")
            console.print(f"Seed: {_state_text(self.result.seed)}")
            console.print(f"Preperiod: {self.result.preperiod}")
            console.print(f"Returns to seed: {self.result.returns_to_seed}")
            console.print(f"Maximum non-zero period: {self.result.maximum_nonzero_period}")
            console.print(f"Maximum-length sequence: {self.result.is_maximum_length}")
            if self.result.zero_state:
                console.print("The all-zero state is a fixed point with period 1.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "sequence.lfsr.period",
            "implementation": "educational",
            "inputs": {
                "polynomial": self.result.polynomial.canonical,
                "seed": _state_text(self.result.seed),
            },
            "result": {
                "preperiod": self.result.preperiod,
                "period": self.result.period,
                "returns_to_seed": self.result.returns_to_seed,
                "maximum_nonzero_period": self.result.maximum_nonzero_period,
                "is_maximum_length": self.result.is_maximum_length,
                "zero_state": self.result.zero_state,
            },
            "trace": [],
            "warnings": [
                "Maximum period does not make a standalone LFSR cryptographically secure."
            ],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [rf"T={self.result.period}"]
        if explain:
            lines.append(rf"T_{{\max}}=2^{{{self.result.polynomial.degree}}}-1")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class LFSRDiagramView:
    """Render the fixed LFSR convention as a register diagram."""

    result: LFSRDiagramResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        stages = " -> ".join(f"[{stage}]" for stage in self.result.stages)
        console.print(f"feedback -> {stages} -> output ({self.result.output_stage})", markup=False)
        console.print("Taps: " + ", ".join(self.result.tap_stages))
        if explain:
            console.print(f"Polynomial: {self.result.polynomial.canonical}")
            console.print("Shift direction: right")
            console.print("New feedback enters s_(m-1); s_0 is emitted.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "sequence.lfsr.diagram",
            "implementation": "educational",
            "inputs": {"polynomial": self.result.polynomial.canonical},
            "result": dataclass_to_dict(self.result),
            "trace": [],
            "warnings": [],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [rf"C(x)={self.result.polynomial.canonical}"]
        if explain:
            lines.append(r"[s_{m-1},\ldots,s_1,s_0]\longrightarrow\text{right}")
        return "\\\n".join(lines)


@dataclass(frozen=True, slots=True)
class SequenceAnalysisView:
    """Render elementary periodic binary-sequence analysis."""

    result: SequenceAnalysisResult

    def render_human(self, console: Console, *, explain: bool) -> None:
        summary = Table("Property", "Value")
        summary.add_row("Length", str(self.result.length))
        summary.add_row("Zeros", str(self.result.zeros))
        summary.add_row("Ones", str(self.result.ones))
        summary.add_row("Balance difference", str(self.result.balance_difference))
        summary.add_row("Balanced", str(self.result.balanced))
        summary.add_row("Fundamental period", str(self.result.fundamental_period))
        console.print(summary)
        runs = Table("Bit", "Run length", "Count")
        for run in self.result.runs:
            runs.add_row(str(run.bit), str(run.length), str(run.count))
        console.print(runs)
        correlation = Table("Lag", "C(lag)", "Normalized")
        for item in self.result.autocorrelation:
            correlation.add_row(str(item.lag), str(item.value), f"{item.normalized:.6f}")
        console.print(correlation)
        if self.result.autocorrelation_truncated:
            console.print("Autocorrelation output was truncated at the configured lag limit.")
        if explain:
            console.print("Runs are counted cyclically; first and last equal symbols are merged.")
            console.print("C(lag) = coincidences - differences under periodic indexing.")

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "command": "sequence.analyze",
            "implementation": "educational",
            "inputs": {"sequence": self.result.sequence},
            "result": {
                "length": self.result.length,
                "zeros": self.result.zeros,
                "ones": self.result.ones,
                "balance_difference": self.result.balance_difference,
                "balanced": self.result.balanced,
                "fundamental_period": self.result.fundamental_period,
                "runs": [dataclass_to_dict(run) for run in self.result.runs],
                "autocorrelation": [
                    dataclass_to_dict(item) for item in self.result.autocorrelation
                ],
                "autocorrelation_truncated": self.result.autocorrelation_truncated,
            },
            "trace": [],
            "warnings": [
                "Period, balance, runs, and autocorrelation are not sufficient "
                "for cryptographic security."
            ],
            "explanation_included": explain,
        }

    def render_latex(self, *, explain: bool) -> str:
        lines = [
            rf"N={self.result.length}",
            rf"N_0={self.result.zeros},\quad N_1={self.result.ones}",
            rf"T={self.result.fundamental_period}",
        ]
        if explain:
            lines.append(r"C(\tau)=\sum_{i=0}^{N-1}(-1)^{s_i\oplus s_{(i+\tau)\bmod N}}")
        return "\\\n".join(lines)
