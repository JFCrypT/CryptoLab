from __future__ import annotations

from json import loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_ecc_help_and_curve_inspection() -> None:
    help_result = runner.invoke(app, ["public-key", "ecc", "--help"])
    assert help_result.exit_code == 0
    assert "inspect" in help_result.stdout
    assert "multiply" in help_result.stdout
    assert "subgroup" in help_result.stdout

    result = runner.invoke(
        app,
        ["--format", "json", "public-key", "ecc", "inspect", "17", "2", "2"],
    )
    assert result.exit_code == 0
    payload = loads(result.stdout)
    assert payload["result"]["group_order"] == 19
    assert len(payload["result"]["finite_points"]) == 18


def test_ecc_point_operations_cli() -> None:
    doubled = runner.invoke(
        app,
        ["--explain", "public-key", "ecc", "add", "17", "2", "2", "5:1", "5:1"],
    )
    assert doubled.exit_code == 0
    assert "5:1 + 5:1 = 6:3" in doubled.stdout
    assert "doubling" in doubled.stdout

    multiplied = runner.invoke(
        app,
        ["--explain", "public-key", "ecc", "multiply", "17", "2", "2", "3", "5:1"],
    )
    assert multiplied.exit_code == 0
    assert "3 * 5:1 = 10:6" in multiplied.stdout

    negated = runner.invoke(
        app,
        ["public-key", "ecc", "negate", "17", "2", "2", "5:1"],
    )
    assert negated.exit_code == 0
    assert "5:16" in negated.stdout

    subgroup = runner.invoke(
        app,
        ["public-key", "ecc", "subgroup", "17", "2", "2", "5:1"],
    )
    assert subgroup.exit_code == 0
    assert "Point order: 19" in subgroup.stdout


def test_ecc_cli_validation() -> None:
    singular = runner.invoke(app, ["public-key", "ecc", "inspect", "17", "0", "0"])
    assert singular.exit_code == 3
    assert "singular" in singular.stderr

    invalid_point = runner.invoke(
        app,
        ["public-key", "ecc", "add", "17", "2", "2", "5:2", "5:1"],
    )
    assert invalid_point.exit_code == 3
    assert "not on" in invalid_point.stderr

    oversized = runner.invoke(app, ["public-key", "ecc", "inspect", "263", "1", "1"])
    assert oversized.exit_code == 5
