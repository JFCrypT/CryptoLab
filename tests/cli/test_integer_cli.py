from __future__ import annotations

from json import loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_root_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Applied Cryptography" in result.stdout
    assert "integer" in result.stdout


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.stdout


def test_division_human_output() -> None:
    result = runner.invoke(app, ["--no-color", "--explain", "integer", "divide", "-17", "5"])
    assert result.exit_code == 0
    assert "-17 = 5(-4) + 3" in result.stdout
    assert "0 <= 3 < 5" in result.stdout


def test_division_json_output() -> None:
    result = runner.invoke(
        app,
        ["--format", "json", "integer", "divide", "-17", "-5"],
    )
    assert result.exit_code == 0
    payload = loads(result.stdout)
    assert payload["command"] == "integer.divide"
    assert payload["result"]["quotient"] == 4
    assert payload["result"]["remainder"] == 3


def test_extended_gcd_json_trace() -> None:
    result = runner.invoke(
        app,
        ["--format", "json", "--explain", "integer", "extended-gcd", "250", "110"],
    )
    assert result.exit_code == 0
    payload = loads(result.stdout)
    assert payload["result"]["gcd"] == 10
    assert payload["result"]["identity_holds"] is True
    assert payload["trace"]


def test_domain_error_exit_code() -> None:
    result = runner.invoke(app, ["integer", "divide", "10", "0"])
    assert result.exit_code == 3
    assert "undefined for divisor zero" in result.stderr


def test_all_integer_commands_execute() -> None:
    commands = [
        ["integer", "divides", "5", "35"],
        ["integer", "divisors", "12", "--kind", "all"],
        ["integer", "gcd", "250", "110"],
        ["integer", "lcm", "12", "18"],
        ["--explain", "integer", "euclid", "250", "110"],
        ["integer", "prime-test", "97"],
        ["integer", "factor", "-360"],
    ]
    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 0, result.stderr


def test_latex_output() -> None:
    result = runner.invoke(app, ["--format", "latex", "integer", "gcd", "12", "18"])
    assert result.exit_code == 0
    assert "operatorname" in result.stdout


def test_output_file(tmp_path) -> None:
    output = tmp_path / "division.json"
    result = runner.invoke(
        app,
        ["--format", "json", "--output", str(output), "integer", "divide", "17", "5"],
    )
    assert result.exit_code == 0
    assert '"quotient": 3' in output.read_text(encoding="utf-8")
