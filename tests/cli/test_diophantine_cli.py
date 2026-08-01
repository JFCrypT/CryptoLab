from __future__ import annotations

from json import loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_solve_human_output() -> None:
    result = runner.invoke(app, ["--no-color", "diophantine", "solve", "2", "-5", "1"])
    assert result.exit_code == 0
    assert "General solution" in result.stdout
    assert "t in Z" in result.stdout


def test_unsolvable_json_output() -> None:
    result = runner.invoke(
        app,
        ["--format", "json", "diophantine", "solve", "6", "-9", "8"],
    )
    assert result.exit_code == 0
    payload = loads(result.stdout)
    assert payload["result"]["solvable"] is False
    assert payload["result"]["kind"] == "none"


def test_verify_command() -> None:
    result = runner.invoke(app, ["diophantine", "verify", "2", "-5", "1", "3", "1"])
    assert result.exit_code == 0
    assert "is a solution" in result.stdout


def test_latex_output() -> None:
    result = runner.invoke(
        app,
        ["--format", "latex", "diophantine", "solve", "33", "17", "1"],
    )
    assert result.exit_code == 0
    assert "mathbb" in result.stdout
