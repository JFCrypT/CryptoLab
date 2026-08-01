"""Modular-arithmetic CLI commands."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from cryptolab.cli.common import execute
from cryptolab.exceptions import CryptoLabError
from cryptolab.mathematics.modular import (
    Congruence,
    generalized_crt,
    modular_add,
    modular_inverse,
    modular_multiply,
    modular_power,
    modular_subtract,
    normalize,
    solve_linear_congruence,
    units,
    zero_divisors,
)
from cryptolab.rendering.modular import (
    CRTView,
    LinearCongruenceView,
    ModularInverseView,
    ModularPowerView,
    ModularScalarView,
    ResidueCollectionView,
)

if TYPE_CHECKING:
    from cryptolab.rendering.common import SupportsRender

CONGRUENCE_PART_COUNT = 2


app = typer.Typer(
    name="modular",
    help="Compute and explain modular arithmetic over canonical representatives.",
    no_args_is_help=True,
)


def _run(context: typer.Context, factory: Callable[[], SupportsRender]) -> None:
    try:
        execute(context, factory())
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


def _parse_congruence(value: str) -> Congruence:
    normalized = value.removeprefix("=")
    pieces = normalized.split(":")
    if len(pieces) != CONGRUENCE_PART_COUNT:
        raise typer.BadParameter("Use RESIDUE:MODULUS, for example 5:7.")
    try:
        residue, modulus = (int(piece) for piece in pieces)
    except ValueError as error:
        raise typer.BadParameter("Residue and modulus must be decimal integers.") from error
    return Congruence(residue=residue, modulus=modulus)


@app.command("normalize", context_settings={"ignore_unknown_options": True})
def normalize_command(
    context: typer.Context,
    value: Annotated[int, typer.Argument(help="Integer to normalize.")],
    modulus: Annotated[int, typer.Argument(help="Modulus n, with n >= 2.")],
) -> None:
    """Return the canonical representative modulo n."""

    _run(
        context,
        lambda: ModularScalarView(
            command="modular.normalize",
            label="normalize",
            inputs={"value": value, "modulus": modulus},
            modulus=modulus,
            value=normalize(value, modulus),
        ),
    )


@app.command("add", context_settings={"ignore_unknown_options": True})
def add_command(
    context: typer.Context,
    a: Annotated[int, typer.Argument(help="First integer.")],
    b: Annotated[int, typer.Argument(help="Second integer.")],
    modulus: Annotated[int, typer.Argument(help="Modulus n, with n >= 2.")],
) -> None:
    """Add two integers modulo n."""

    _run(
        context,
        lambda: ModularScalarView.from_result(
            command="modular.add",
            label="add",
            inputs={"a": a, "b": b, "modulus": modulus},
            result=modular_add(a, b, modulus),
        ),
    )


@app.command("subtract", context_settings={"ignore_unknown_options": True})
def subtract_command(
    context: typer.Context,
    a: Annotated[int, typer.Argument(help="Integer minuend.")],
    b: Annotated[int, typer.Argument(help="Integer subtrahend.")],
    modulus: Annotated[int, typer.Argument(help="Modulus n, with n >= 2.")],
) -> None:
    """Subtract two integers modulo n."""

    _run(
        context,
        lambda: ModularScalarView.from_result(
            command="modular.subtract",
            label="subtract",
            inputs={"a": a, "b": b, "modulus": modulus},
            result=modular_subtract(a, b, modulus),
        ),
    )


@app.command("multiply", context_settings={"ignore_unknown_options": True})
def multiply_command(
    context: typer.Context,
    a: Annotated[int, typer.Argument(help="First integer.")],
    b: Annotated[int, typer.Argument(help="Second integer.")],
    modulus: Annotated[int, typer.Argument(help="Modulus n, with n >= 2.")],
) -> None:
    """Multiply two integers modulo n."""

    _run(
        context,
        lambda: ModularScalarView.from_result(
            command="modular.multiply",
            label="multiply",
            inputs={"a": a, "b": b, "modulus": modulus},
            result=modular_multiply(a, b, modulus),
        ),
    )


@app.command("power", context_settings={"ignore_unknown_options": True})
def power_command(
    context: typer.Context,
    base: Annotated[int, typer.Argument(help="Integer base.")],
    exponent: Annotated[int, typer.Argument(help="Non-negative integer exponent.")],
    modulus: Annotated[int, typer.Argument(help="Modulus n, with n >= 2.")],
) -> None:
    """Compute a modular power by square-and-multiply."""

    _run(context, lambda: ModularPowerView(modular_power(base, exponent, modulus)))


@app.command("inverse", context_settings={"ignore_unknown_options": True})
def inverse_command(
    context: typer.Context,
    value: Annotated[int, typer.Argument(help="Integer whose inverse is requested.")],
    modulus: Annotated[int, typer.Argument(help="Modulus n, with n >= 2.")],
) -> None:
    """Determine and compute a multiplicative inverse modulo n."""

    _run(context, lambda: ModularInverseView(modular_inverse(value, modulus)))


@app.command("units", context_settings={"ignore_unknown_options": True})
def units_command(
    context: typer.Context,
    modulus: Annotated[int, typer.Argument(help="Bounded modulus n, with n >= 2.")],
) -> None:
    """Enumerate the multiplicative units of Z_n."""

    _run(context, lambda: ResidueCollectionView(units(modulus)))


@app.command("zero-divisors", context_settings={"ignore_unknown_options": True})
def zero_divisors_command(
    context: typer.Context,
    modulus: Annotated[int, typer.Argument(help="Bounded modulus n, with n >= 2.")],
) -> None:
    """Enumerate the non-zero zero divisors of Z_n."""

    _run(context, lambda: ResidueCollectionView(zero_divisors(modulus)))


@app.command("solve-linear", context_settings={"ignore_unknown_options": True})
def solve_linear_command(
    context: typer.Context,
    a: Annotated[int, typer.Argument(help="Coefficient a in ax ≡ b (mod n).")],
    b: Annotated[int, typer.Argument(help="Right-hand side b in ax ≡ b (mod n).")],
    modulus: Annotated[int, typer.Argument(help="Modulus n, with n >= 2.")],
) -> None:
    """Solve a linear congruence and list every canonical solution."""

    _run(context, lambda: LinearCongruenceView(solve_linear_congruence(a, b, modulus)))


@app.command("crt")
def crt_command(
    context: typer.Context,
    congruence: Annotated[
        list[str],
        typer.Option(
            "--congruence",
            "-c",
            help="Repeat RESIDUE:MODULUS for each congruence.",
        ),
    ],
) -> None:
    """Solve a possibly non-coprime congruence system by generalized CRT."""

    parsed = tuple(_parse_congruence(value) for value in congruence)
    _run(context, lambda: CRTView(generalized_crt(parsed)))
