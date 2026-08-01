"""Root CryptoLab CLI application."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from cryptolab.cli.common import build_output_options
from cryptolab.cli.diophantine import app as diophantine_app
from cryptolab.cli.integer import app as integer_app
from cryptolab.cli.modular import app as modular_app
from cryptolab.metadata import PROJECT_TITLE, __version__
from cryptolab.rendering.common import OutputFormat

app = typer.Typer(
    name="cryptolab",
    help=(
        "CryptoLab — Applied Cryptography Laboratory. "
        "Didactic laboratory for cryptographic mathematics and applied cryptography."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(integer_app, name="integer")
app.add_typer(diophantine_app, name="diophantine")
app.add_typer(modular_app, name="modular")


def version_callback(value: bool) -> None:
    """Print the target project version and exit."""

    if value:
        typer.echo(f"{PROJECT_TITLE} {__version__}")
        raise typer.Exit


@app.callback()
def root_callback(
    context: typer.Context,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Select human, JSON, or LaTeX output."),
    ] = OutputFormat.HUMAN,
    explain: Annotated[
        bool,
        typer.Option("--explain", help="Include structured intermediate information."),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write output atomically to this path."),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable terminal colors."),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Enable internal diagnostics without revealing secrets."),
    ] = False,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show the target project version and exit.",
        ),
    ] = None,
) -> None:
    """Configure global output behavior for all CryptoLab commands."""

    del version
    context.obj = build_output_options(
        output_format=output_format,
        explain=explain,
        output=output,
        no_color=no_color,
        debug=debug,
    )


def main() -> None:
    """Run the CryptoLab command-line application."""

    app()
