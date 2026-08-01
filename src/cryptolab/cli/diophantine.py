"""Linear Diophantine equation CLI commands."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from cryptolab.cli.common import execute
from cryptolab.exceptions import CryptoLabError
from cryptolab.mathematics.diophantine import solve_diophantine, verify_diophantine_solution
from cryptolab.rendering.diophantine import DiophantineSolutionView, DiophantineVerificationView

if TYPE_CHECKING:
    from cryptolab.rendering.common import SupportsRender

app = typer.Typer(
    name="diophantine",
    help="Solve and verify linear Diophantine equations ax + by = c.",
    no_args_is_help=True,
)


def _run(context: typer.Context, factory: Callable[[], SupportsRender]) -> None:
    try:
        execute(context, factory())
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


@app.command("solve", context_settings={"ignore_unknown_options": True})
def solve_command(
    context: typer.Context,
    a: Annotated[int, typer.Argument(help="Coefficient a of x.")],
    b: Annotated[int, typer.Argument(help="Coefficient b of y.")],
    c: Annotated[int, typer.Argument(help="Independent term c.")],
) -> None:
    """Solve ax + by = c over the integers."""

    _run(context, lambda: DiophantineSolutionView(solve_diophantine(a, b, c)))


@app.command("verify", context_settings={"ignore_unknown_options": True})
def verify_command(
    context: typer.Context,
    a: Annotated[int, typer.Argument(help="Coefficient a of x.")],
    b: Annotated[int, typer.Argument(help="Coefficient b of y.")],
    c: Annotated[int, typer.Argument(help="Independent term c.")],
    x: Annotated[int, typer.Argument(help="Candidate integer value for x.")],
    y: Annotated[int, typer.Argument(help="Candidate integer value for y.")],
) -> None:
    """Verify whether an integer pair solves ax + by = c."""

    _run(
        context,
        lambda: DiophantineVerificationView(
            a=a,
            b=b,
            c=c,
            x=x,
            y=y,
            valid=verify_diophantine_solution(a, b, c, x, y),
        ),
    )
