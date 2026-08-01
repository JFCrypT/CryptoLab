"""CLI commands for LFSR generation and elementary binary-sequence analysis."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from cryptolab.cli.common import execute
from cryptolab.exceptions import CryptoLabError
from cryptolab.rendering.sequences import (
    LFSRDiagramView,
    LFSRGenerationView,
    LFSRPeriodView,
    SequenceAnalysisView,
)
from cryptolab.sequences.analysis import analyze_binary_sequence
from cryptolab.sequences.lfsr import (
    describe_lfsr,
    detect_lfsr_period,
    generate_lfsr,
    parse_feedback_polynomial,
    parse_seed,
)

if TYPE_CHECKING:
    from cryptolab.rendering.common import SupportsRender

app = typer.Typer(
    name="sequence",
    help="Generate and analyze educational binary pseudorandom sequences.",
    no_args_is_help=True,
)
lfsr_app = typer.Typer(
    name="lfsr",
    help="Use the fixed CryptoLab Fibonacci right-shift LFSR convention.",
    no_args_is_help=True,
)
app.add_typer(lfsr_app, name="lfsr")


def _run(context: typer.Context, factory: Callable[[], SupportsRender]) -> None:
    try:
        execute(context, factory())
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


@lfsr_app.command("generate")
def lfsr_generate_command(
    context: typer.Context,
    polynomial: Annotated[str, typer.Argument(help="Canonical polynomial, for example x^3+x^2+1.")],
    seed: Annotated[str, typer.Argument(help="Seed ordered as [s_(m-1), ..., s_0].")],
    length: Annotated[int, typer.Argument(help="Positive output length in bits.")],
) -> None:
    """Generate an LFSR sequence and optionally show every state transition."""

    def factory() -> LFSRGenerationView:
        parsed = parse_feedback_polynomial(polynomial)
        parsed_seed = parse_seed(seed, parsed.degree)
        return LFSRGenerationView(generate_lfsr(parsed, parsed_seed, length))

    _run(context, factory)


@lfsr_app.command("period")
def lfsr_period_command(
    context: typer.Context,
    polynomial: Annotated[str, typer.Argument(help="Canonical polynomial, for example x^3+x^2+1.")],
    seed: Annotated[str, typer.Argument(help="Seed ordered as [s_(m-1), ..., s_0].")],
) -> None:
    """Detect the cycle and period reached from one seed."""

    def factory() -> LFSRPeriodView:
        parsed = parse_feedback_polynomial(polynomial)
        parsed_seed = parse_seed(seed, parsed.degree)
        return LFSRPeriodView(detect_lfsr_period(parsed, parsed_seed))

    _run(context, factory)


@lfsr_app.command("diagram")
def lfsr_diagram_command(
    context: typer.Context,
    polynomial: Annotated[str, typer.Argument(help="Canonical polynomial, for example x^3+x^2+1.")],
) -> None:
    """Display the register ordering, shift direction, output stage, and taps."""

    _run(context, lambda: LFSRDiagramView(describe_lfsr(parse_feedback_polynomial(polynomial))))


@app.command("analyze")
def sequence_analyze_command(
    context: typer.Context,
    sequence: Annotated[str, typer.Argument(help="Non-empty finite binary sequence.")],
    max_lag: Annotated[
        int | None,
        typer.Option("--max-lag", help="Largest periodic autocorrelation lag to display."),
    ] = None,
) -> None:
    """Compute period, balance, cyclic runs, and periodic autocorrelation."""

    _run(
        context,
        lambda: SequenceAnalysisView(analyze_binary_sequence(sequence, max_lag=max_lag)),
    )
