from __future__ import annotations

from json import loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_root_help_lists_new_groups() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "diophantine" in result.stdout
    assert "modular" in result.stdout


def test_power_explain_output() -> None:
    result = runner.invoke(
        app,
        ["--no-color", "--explain", "modular", "power", "14", "15", "29"],
    )
    assert result.exit_code == 0
    assert "square-and-multiply" in result.stdout


def test_inverse_nonexistence_is_valid_result() -> None:
    result = runner.invoke(app, ["modular", "inverse", "54", "200"])
    assert result.exit_code == 0
    assert "no multiplicative inverse" in result.stdout


def test_linear_congruence_json() -> None:
    result = runner.invoke(
        app,
        ["--format", "json", "modular", "solve-linear", "15", "30", "55"],
    )
    assert result.exit_code == 0
    payload = loads(result.stdout)
    assert payload["result"]["solutions"] == [2, 13, 24, 35, 46]


def test_generalized_crt() -> None:
    result = runner.invoke(
        app,
        [
            "--no-color",
            "modular",
            "crt",
            "-c",
            "5:7",
            "-c",
            "0:6",
            "-c=-1:5",
        ],
    )
    assert result.exit_code == 0, result.stderr
    assert "x ≡ 54 (mod 210)" in result.stdout


def test_malformed_crt_input() -> None:
    result = runner.invoke(app, ["modular", "crt", "-c", "invalid"])
    assert result.exit_code == 2
    assert "RESIDUE:MODULUS" in result.stderr


def test_invalid_modulus_exit_code() -> None:
    result = runner.invoke(app, ["modular", "normalize", "5", "1"])
    assert result.exit_code == 3
    assert "greater than or equal to 2" in result.stderr


def test_all_modular_commands_execute() -> None:
    commands = [
        ["modular", "normalize", "-9", "15"],
        ["modular", "add", "14", "20", "9"],
        ["modular", "subtract", "3", "10", "7"],
        ["modular", "multiply", "12", "8", "13"],
        ["modular", "units", "15"],
        ["modular", "zero-divisors", "15"],
    ]
    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 0, result.stderr


def test_crt_requires_at_least_one_congruence() -> None:
    result = runner.invoke(app, ["modular", "crt"])
    assert result.exit_code == 2
    assert "Missing option" in result.stderr
