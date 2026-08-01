from __future__ import annotations

from json import loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_root_help_lists_sequence() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "sequence" in result.stdout


def test_lfsr_generate_period_and_diagram() -> None:
    generated = runner.invoke(
        app,
        ["sequence", "lfsr", "generate", "x^3+x^2+1", "101", "21"],
    )
    assert generated.exit_code == 0
    assert generated.stdout.strip() == "101001110100111010011"

    period = runner.invoke(
        app,
        ["--format", "json", "sequence", "lfsr", "period", "x^3+x^2+1", "101"],
    )
    assert period.exit_code == 0
    assert loads(period.stdout)["result"]["period"] == 7

    diagram = runner.invoke(
        app,
        ["--no-color", "--explain", "sequence", "lfsr", "diagram", "x^3+x^2+1"],
    )
    assert diagram.exit_code == 0
    assert "[s_2] -> [s_1] -> [s_0]" in diagram.stdout
    assert "output (s_0)" in diagram.stdout


def test_sequence_analysis_and_invalid_polynomial() -> None:
    analyzed = runner.invoke(
        app,
        ["--format", "json", "sequence", "analyze", "1010011", "--max-lag", "6"],
    )
    assert analyzed.exit_code == 0
    result = loads(analyzed.stdout)["result"]
    assert result["fundamental_period"] == 7
    assert [item["value"] for item in result["autocorrelation"]] == [7, -1, -1, -1, -1, -1, -1]

    invalid = runner.invoke(app, ["sequence", "lfsr", "period", "D^3+D^2+1", "101"])
    assert invalid.exit_code == 3
    assert "canonical x notation" in invalid.stderr
