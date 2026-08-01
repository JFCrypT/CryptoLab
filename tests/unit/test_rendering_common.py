from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from rich.console import Console

from cryptolab.exceptions import OutputError
from cryptolab.rendering.common import (
    OutputFormat,
    OutputOptions,
    dataclass_to_dict,
    emit,
)


@dataclass(frozen=True)
class SampleData:
    value: int


class SampleView:
    def render_human(self, console: Console, *, explain: bool) -> None:
        console.print(f"human:{explain}")

    def render_json(self, *, explain: bool) -> dict[str, object]:
        return {"explain": explain, "value": 7}

    def render_latex(self, *, explain: bool) -> str:
        return rf"x={7};e={explain}"


def test_dataclass_to_dict() -> None:
    assert dataclass_to_dict(SampleData(7)) == {"value": 7}
    with pytest.raises(TypeError):
        dataclass_to_dict(object())


def test_emit_human_to_file(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "result.txt"
    emit(SampleView(), OutputOptions(output=destination, explain=True))
    assert destination.read_text(encoding="utf-8") == "human:True\n"


def test_emit_json_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    emit(SampleView(), OutputOptions(format=OutputFormat.JSON, explain=True))
    captured = capsys.readouterr()
    assert '"value": 7' in captured.out


def test_emit_latex_to_file(tmp_path: Path) -> None:
    destination = tmp_path / "result.tex"
    emit(SampleView(), OutputOptions(format=OutputFormat.LATEX, output=destination))
    assert destination.read_text(encoding="utf-8") == "x=7;e=False\n"


def test_emit_output_error(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(OutputError):
        emit(SampleView(), OutputOptions(format=OutputFormat.JSON, output=directory))
