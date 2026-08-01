"""Integer-arithmetic CLI commands."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from cryptolab.cli.common import execute
from cryptolab.exceptions import CryptoLabError
from cryptolab.mathematics.integers import (
    DivisorKind,
    divides,
    divisors,
    euclidean_algorithm,
    euclidean_division,
    extended_gcd,
    factor_integer,
    gcd,
    is_prime,
    lcm,
)
from cryptolab.rendering.integer import (
    BooleanView,
    DivisionView,
    DivisorsView,
    EuclideanAlgorithmView,
    ExtendedGCDView,
    FactorizationView,
    PrimeTestView,
    ScalarView,
)

if TYPE_CHECKING:
    from cryptolab.rendering.common import SupportsRender

app = typer.Typer(
    name="integer",
    help="Compute and explain elementary integer arithmetic used in cryptography.",
    no_args_is_help=True,
)


def _run(context: typer.Context, factory: Callable[[], SupportsRender]) -> None:
    try:
        renderable = factory()
        execute(context, renderable)
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


@app.command("divide", context_settings={"ignore_unknown_options": True})
def divide_command(
    context: typer.Context,
    dividend: Annotated[int, typer.Argument(help="Integer dividend a.")],
    divisor: Annotated[int, typer.Argument(help="Non-zero integer divisor b.")],
) -> None:
    """Perform Euclidean division with a non-negative remainder."""

    _run(context, lambda: DivisionView(euclidean_division(dividend, divisor)))


@app.command("divides", context_settings={"ignore_unknown_options": True})
def divides_command(
    context: typer.Context,
    divisor: Annotated[int, typer.Argument(help="Candidate non-zero divisor.")],
    dividend: Annotated[int, typer.Argument(help="Integer tested for divisibility.")],
) -> None:
    """Determine whether one integer divides another."""

    _run(
        context,
        lambda: BooleanView(
            command="integer.divides",
            label=f"{divisor} divides {dividend}",
            value=divides(divisor, dividend),
            inputs={"divisor": divisor, "dividend": dividend},
        ),
    )


@app.command("divisors", context_settings={"ignore_unknown_options": True})
def divisors_command(
    context: typer.Context,
    n: Annotated[int, typer.Argument(help="Non-zero integer to inspect.")],
    kind: Annotated[
        DivisorKind,
        typer.Option("--kind", help="Select positive, negative, or all divisors."),
    ] = DivisorKind.POSITIVE,
) -> None:
    """Enumerate the divisors of a bounded educational integer."""

    _run(context, lambda: DivisorsView(n=n, kind=kind, values=divisors(n, kind)))


@app.command("gcd", context_settings={"ignore_unknown_options": True})
def gcd_command(
    context: typer.Context,
    a: Annotated[int, typer.Argument(help="First integer.")],
    b: Annotated[int, typer.Argument(help="Second integer.")],
) -> None:
    """Compute the non-negative greatest common divisor."""

    _run(context, lambda: ScalarView("integer.gcd", "gcd", a, b, gcd(a, b)))


@app.command("lcm", context_settings={"ignore_unknown_options": True})
def lcm_command(
    context: typer.Context,
    a: Annotated[int, typer.Argument(help="First integer.")],
    b: Annotated[int, typer.Argument(help="Second integer.")],
) -> None:
    """Compute the non-negative least common multiple."""

    _run(context, lambda: ScalarView("integer.lcm", "lcm", a, b, lcm(a, b)))


@app.command("euclid", context_settings={"ignore_unknown_options": True})
def euclid_command(
    context: typer.Context,
    a: Annotated[int, typer.Argument(help="First integer.")],
    b: Annotated[int, typer.Argument(help="Second integer.")],
) -> None:
    """Compute a gcd and optionally show the Euclidean division trace."""

    _run(context, lambda: EuclideanAlgorithmView(euclidean_algorithm(a, b)))


@app.command("extended-gcd", context_settings={"ignore_unknown_options": True})
def extended_gcd_command(
    context: typer.Context,
    a: Annotated[int, typer.Argument(help="First integer.")],
    b: Annotated[int, typer.Argument(help="Second integer.")],
) -> None:
    """Compute a gcd, Bézout coefficients, and an optional execution trace."""

    _run(context, lambda: ExtendedGCDView(extended_gcd(a, b)))


@app.command("prime-test", context_settings={"ignore_unknown_options": True})
def prime_test_command(
    context: typer.Context,
    n: Annotated[int, typer.Argument(help="Non-negative bounded integer.")],
) -> None:
    """Classify a bounded integer using deterministic educational trial division."""

    _run(context, lambda: PrimeTestView(is_prime(n)))


@app.command("factor", context_settings={"ignore_unknown_options": True})
def factor_command(
    context: typer.Context,
    n: Annotated[int, typer.Argument(help="Non-zero bounded integer.")],
) -> None:
    """Factor a bounded integer using deterministic educational trial division."""

    _run(context, lambda: FactorizationView(factor_integer(n)))
