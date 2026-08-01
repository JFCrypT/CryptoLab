"""Shared CLI helpers."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from cryptolab.exceptions import CryptoLabError
from cryptolab.rendering.common import OutputFormat, OutputOptions, SupportsRender, emit


def options_from_context(context: typer.Context) -> OutputOptions:
    """Return validated root output options from a Typer context."""

    if isinstance(context.obj, OutputOptions):
        return context.obj
    return OutputOptions()


def execute(context: typer.Context, renderable: SupportsRender) -> None:
    """Emit a successful result or translate expected failures into exit codes."""

    try:
        emit(renderable, options_from_context(context))
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


def build_output_options(
    *,
    output_format: OutputFormat,
    explain: bool,
    output: Path | None,
    no_color: bool,
    debug: bool,
) -> OutputOptions:
    """Create immutable global output options."""

    return OutputOptions(
        format=output_format,
        explain=explain,
        output=output,
        no_color=no_color,
        debug=debug,
    )
