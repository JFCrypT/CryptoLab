from __future__ import annotations

from json import loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_root_help_lists_algebra() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "algebra" in result.stdout


def test_zn_human_output() -> None:
    result = runner.invoke(app, ["--no-color", "--explain", "algebra", "zn", "15"])
    assert result.exit_code == 0
    assert "Integral domain" in result.stdout
    assert "Non-zero zero divisors" in result.stdout


def test_additive_order_json() -> None:
    result = runner.invoke(
        app,
        ["--format", "json", "algebra", "order", "5", "17"],
    )
    assert result.exit_code == 0
    payload = loads(result.stdout)
    assert payload["result"]["order"] == 17


def test_multiplicative_subgroup() -> None:
    result = runner.invoke(
        app,
        ["algebra", "subgroup", "4", "15", "--operation", "multiplicative"],
    )
    assert result.exit_code == 0
    assert "{1, 4}" in result.stdout


def test_generators_and_primitive_roots() -> None:
    additive = runner.invoke(app, ["algebra", "generators", "12"])
    assert additive.exit_code == 0
    assert "1, 5, 7, 11" in additive.stdout

    roots = runner.invoke(app, ["algebra", "primitive-roots", "17"])
    assert roots.exit_code == 0
    assert "3, 5, 6, 7, 10, 11, 12, 14" in roots.stdout


def test_invalid_multiplicative_element_exit_code() -> None:
    result = runner.invoke(
        app,
        ["algebra", "order", "6", "15", "--operation", "multiplicative"],
    )
    assert result.exit_code == 3
    assert "only for units" in result.stderr
