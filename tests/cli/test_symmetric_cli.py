from __future__ import annotations

from json import loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_root_help_lists_symmetric() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "symmetric" in result.stdout


def test_xor_truth_bits_and_bytes() -> None:
    truth = runner.invoke(app, ["symmetric", "xor", "truth-table"])
    assert truth.exit_code == 0
    assert "x XOR y" in truth.stdout

    bits = runner.invoke(app, ["symmetric", "xor", "bits", "1011", "1111"])
    assert bits.exit_code == 0
    assert bits.stdout.strip() == "0100"

    byte_result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "symmetric",
            "xor",
            "bytes",
            "--left-hex",
            "beca",
            "--right-hex",
            "fe12",
        ],
    )
    assert byte_result.exit_code == 0
    assert loads(byte_result.stdout)["result"]["output_hex"] == "40d8"


def test_vernam_round_trip_and_requirements() -> None:
    encrypted = runner.invoke(
        app,
        [
            "symmetric",
            "vernam",
            "encrypt",
            "--message-hex",
            "beca",
            "--key-hex",
            "fe12",
        ],
    )
    assert encrypted.exit_code == 0
    assert encrypted.stdout.strip() == "40d8"

    decrypted = runner.invoke(
        app,
        [
            "symmetric",
            "vernam",
            "decrypt",
            "--ciphertext-hex",
            "40d8",
            "--key-hex",
            "fe12",
        ],
    )
    assert decrypted.exit_code == 0
    assert decrypted.stdout.strip() == "beca"

    requirements = runner.invoke(app, ["symmetric", "otp", "requirements"])
    assert requirements.exit_code == 0
    assert "uniform-random-key" in requirements.stdout
    assert "cannot prove" in requirements.stdout


def test_explicit_source_and_length_errors() -> None:
    missing = runner.invoke(app, ["symmetric", "xor", "bytes", "--left-hex", "00"])
    assert missing.exit_code == 3
    assert "exactly one source for right" in missing.stderr

    unequal = runner.invoke(
        app,
        [
            "symmetric",
            "vernam",
            "encrypt",
            "--message-hex",
            "00",
            "--key-hex",
            "0001",
        ],
    )
    assert unequal.exit_code == 3
    assert "equal length" in unequal.stderr
