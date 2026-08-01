from __future__ import annotations

from pathlib import Path

import pytest
import typer

from cryptolab.cli.common import build_output_options, execute, options_from_context
from cryptolab.exceptions import OutputError
from cryptolab.rendering.common import OutputFormat, OutputOptions


class FailingView:
    def render_human(self, console: object, *, explain: bool) -> None:
        del console, explain
        raise OutputError("failure")

    def render_json(self, *, explain: bool) -> dict[str, object]:
        del explain
        raise OutputError("failure")

    def render_latex(self, *, explain: bool) -> str:
        del explain
        raise OutputError("failure")


def test_options_from_context_defaults_and_existing() -> None:
    context = typer.Context(typer.core.TyperCommand(name="test"))
    assert options_from_context(context) == OutputOptions()
    context.obj = OutputOptions(explain=True)
    assert options_from_context(context).explain is True


def test_build_output_options() -> None:
    destination = Path("result.json")
    options = build_output_options(
        output_format=OutputFormat.JSON,
        explain=True,
        output=destination,
        no_color=True,
        debug=True,
    )
    assert options == OutputOptions(OutputFormat.JSON, True, destination, True, True)


def test_execute_translates_output_error() -> None:
    context = typer.Context(typer.core.TyperCommand(name="test"))
    with pytest.raises(typer.Exit) as caught:
        execute(context, FailingView())
    assert caught.value.exit_code == 6
