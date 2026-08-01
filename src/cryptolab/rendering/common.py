"""Shared output configuration and emission helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import StrEnum
from json import dumps
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Protocol

from rich.console import Console

from cryptolab.exceptions import OutputError


class OutputFormat(StrEnum):
    """Supported CLI output formats."""

    HUMAN = "human"
    JSON = "json"
    LATEX = "latex"


@dataclass(frozen=True, slots=True)
class OutputOptions:
    """Global output behavior selected by the root CLI."""

    format: OutputFormat = OutputFormat.HUMAN
    explain: bool = False
    output: Path | None = None
    no_color: bool = False
    debug: bool = False


class SupportsRender(Protocol):
    """Protocol implemented by command-specific presentation objects."""

    def render_human(self, console: Console, *, explain: bool) -> None:
        """Render human-readable output."""

    def render_json(self, *, explain: bool) -> dict[str, Any]:
        """Return a JSON-serializable envelope."""

    def render_latex(self, *, explain: bool) -> str:
        """Return LaTeX output."""


def _write_atomic(path: Path, content: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary_path = Path(temporary.name)
        temporary_path.replace(path)
    except OSError as error:
        raise OutputError(f"Unable to write output file: {path}") from error


def emit(renderable: SupportsRender, options: OutputOptions) -> None:
    """Render a command result to stdout or an atomic output file."""

    if options.format is OutputFormat.HUMAN:
        if options.output is None:
            console = Console(no_color=options.no_color)
            renderable.render_human(console, explain=options.explain)
            return
        recording_console = Console(record=True, force_terminal=False, no_color=True)
        renderable.render_human(recording_console, explain=options.explain)
        _write_atomic(options.output, recording_console.export_text(clear=False))
        return

    if options.format is OutputFormat.JSON:
        payload = renderable.render_json(explain=options.explain)
        content = dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    else:
        content = renderable.render_latex(explain=options.explain).rstrip() + "\n"

    if options.output is None:
        Console(no_color=True, markup=False, highlight=False).print(content, end="")
    else:
        _write_atomic(options.output, content)


def dataclass_to_dict(value: object) -> dict[str, Any]:
    """Convert a dataclass result to a JSON-compatible dictionary."""

    if not is_dataclass(value) or isinstance(value, type):
        raise TypeError("Expected a dataclass instance.")
    converted = asdict(value)
    if not isinstance(converted, dict):  # pragma: no cover
        raise TypeError("Expected dataclass conversion to produce a dictionary.")
    return converted
