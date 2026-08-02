from __future__ import annotations

from json import loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_diffie_hellman_help_and_group_inspection() -> None:
    help_result = runner.invoke(app, ["public-key", "dh", "--help"])
    assert help_result.exit_code == 0
    assert "group" in help_result.stdout
    assert "exchange" in help_result.stdout

    group = runner.invoke(
        app,
        ["--format", "json", "public-key", "dh", "group", "17", "3"],
    )
    assert group.exit_code == 0
    payload = loads(group.stdout)
    assert payload["result"]["is_generator"] is True
    assert payload["result"]["generator_order"] == 16


def test_diffie_hellman_exchange_cli_course_example() -> None:
    result = runner.invoke(
        app,
        ["--explain", "public-key", "dh", "exchange", "17", "3", "13", "11"],
    )
    assert result.exit_code == 0
    assert "Alice shared secret: 6; Bob shared secret: 6" in result.stdout
    assert "Shared secret matches: True" in result.stdout
    assert "HKDF-SHA-256 session key" in result.stdout


def test_diffie_hellman_cli_validation() -> None:
    non_generator = runner.invoke(
        app,
        ["public-key", "dh", "exchange", "17", "4", "13", "11"],
    )
    assert non_generator.exit_code == 3
    assert "requires a generator" in non_generator.stderr

    composite = runner.invoke(app, ["public-key", "dh", "group", "15", "2"])
    assert composite.exit_code == 3
    assert "must be prime" in composite.stderr


def test_diffie_hellman_mitm_cli() -> None:
    result = runner.invoke(
        app,
        [
            "--explain",
            "lab",
            "dh-man-in-the-middle",
            "17",
            "3",
            "13",
            "11",
            "--mallory-alice-private",
            "5",
            "--mallory-bob-private",
            "7",
        ],
    )
    assert result.exit_code == 0
    assert "Mallory matches Alice: True" in result.stdout
    assert "Mallory matches Bob: True" in result.stdout
    assert "different secrets: True" in result.stdout

    registry = runner.invoke(app, ["--format", "json", "lab", "list"])
    assert registry.exit_code == 0
    payload = loads(registry.stdout)
    assert len(payload["result"]["laboratories"]) == 4
    assert all(item["status"] == "implemented" for item in payload["result"]["laboratories"])
