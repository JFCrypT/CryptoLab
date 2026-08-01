from __future__ import annotations

from json import loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_root_help_lists_lab() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "lab" in result.stdout


def test_lab_list_and_caesar_brute_force() -> None:
    listed = runner.invoke(app, ["lab", "list"])
    assert listed.exit_code == 0
    assert "caesar-brute-force" in listed.stdout
    assert "ecb-pattern-leakage" in listed.stdout

    result = runner.invoke(app, ["lab", "caesar-brute-force", "KHOOR"])
    assert result.exit_code == 0
    assert "HELLO" in result.stdout
    assert "Key-space size: 26" in result.stdout


def test_vernam_key_reuse_lab_json() -> None:
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "lab",
            "vernam-key-reuse",
            "--message-one-hex",
            "beca",
            "--message-two-hex",
            "bcee",
            "--key-hex",
            "fe12",
        ],
    )
    assert result.exit_code == 0
    payload = loads(result.stdout)
    assert payload["result"]["identity_holds"] is True
    assert payload["result"]["ciphertext_xor_hex"] == payload["result"]["plaintext_xor_hex"]


def test_vernam_key_reuse_rejects_length_mismatch() -> None:
    result = runner.invoke(
        app,
        [
            "lab",
            "vernam-key-reuse",
            "--message-one-hex",
            "00",
            "--message-two-hex",
            "0001",
            "--key-hex",
            "00",
        ],
    )
    assert result.exit_code == 3
    assert "equal length" in result.stderr
