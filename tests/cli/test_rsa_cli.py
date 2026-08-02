from __future__ import annotations

from json import loads
from pathlib import Path

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_public_key_and_rsa_help() -> None:
    public_key = runner.invoke(app, ["public-key", "--help"])
    assert public_key.exit_code == 0
    assert "rsa" in public_key.stdout
    rsa = runner.invoke(app, ["public-key", "rsa", "--help"])
    assert rsa.exit_code == 0
    assert "educational" in rsa.stdout
    assert "applied" in rsa.stdout
    assert "convert" in rsa.stdout
    assert "compare" in rsa.stdout


def test_educational_rsa_cli_example_and_json() -> None:
    inspected = runner.invoke(
        app,
        ["--format", "json", "public-key", "rsa", "educational", "inspect", "61", "53", "17"],
    )
    assert inspected.exit_code == 0
    payload = loads(inspected.stdout)
    assert payload["result"]["n"] == 3233
    assert payload["result"]["d"] == 2753
    assert payload["result"]["d_carmichael"] == 413

    encrypted = runner.invoke(
        app,
        [
            "public-key",
            "rsa",
            "educational",
            "encrypt",
            "65",
            "--p",
            "61",
            "--q",
            "53",
            "--e",
            "17",
        ],
    )
    assert encrypted.exit_code == 0
    assert encrypted.stdout.strip().endswith("2790")

    decrypted = runner.invoke(
        app,
        [
            "--explain",
            "public-key",
            "rsa",
            "educational",
            "decrypt",
            "2790",
            "--p",
            "61",
            "--q",
            "53",
            "--e",
            "17",
        ],
    )
    assert decrypted.exit_code == 0
    assert "Plaintext representative: 65" in decrypted.stdout
    assert "CRT matches standard" in decrypted.stdout


def test_rsa_conversion_cli() -> None:
    encoded = runner.invoke(
        app,
        ["public-key", "rsa", "convert", "integer-to-bytes", "3233"],
    )
    assert encoded.exit_code == 0
    assert encoded.stdout.strip() == "0ca1"
    decoded = runner.invoke(
        app,
        ["public-key", "rsa", "convert", "bytes-to-integer", "0ca1"],
    )
    assert decoded.exit_code == 0
    assert decoded.stdout.strip() == "3233"

    negative = runner.invoke(
        app,
        ["public-key", "rsa", "convert", "integer-to-bytes", "-1"],
    )
    assert negative.exit_code == 3
    assert "non-negative" in negative.stderr


def test_applied_rsa_cli_complete_workflow(tmp_path: Path) -> None:
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    generated = runner.invoke(
        app,
        [
            "public-key",
            "rsa",
            "applied",
            "generate",
            "--private-key-out",
            str(private_path),
            "--public-key-out",
            str(public_path),
        ],
    )
    assert generated.exit_code == 0
    assert private_path.exists()
    assert public_path.exists()
    assert private_path.stat().st_mode & 0o777 == 0o600

    encrypted = runner.invoke(
        app,
        [
            "public-key",
            "rsa",
            "applied",
            "oaep-encrypt",
            "--public-key-file",
            str(public_path),
            "--plaintext-text",
            "CryptoLab",
        ],
    )
    assert encrypted.exit_code == 0
    ciphertext = "".join(encrypted.stdout.split())
    assert len(ciphertext) == 512

    decrypted = runner.invoke(
        app,
        [
            "public-key",
            "rsa",
            "applied",
            "oaep-decrypt",
            "--private-key-file",
            str(private_path),
            "--ciphertext-hex",
            ciphertext,
        ],
    )
    assert decrypted.exit_code == 0
    assert bytes.fromhex(decrypted.stdout.strip()) == b"CryptoLab"

    signed = runner.invoke(
        app,
        [
            "public-key",
            "rsa",
            "applied",
            "pss-sign",
            "--private-key-file",
            str(private_path),
            "--message-text",
            "CryptoLab",
        ],
    )
    assert signed.exit_code == 0
    signature = "".join(signed.stdout.split())
    assert len(signature) == 512

    verified = runner.invoke(
        app,
        [
            "public-key",
            "rsa",
            "applied",
            "pss-verify",
            "--public-key-file",
            str(public_path),
            "--signature-hex",
            signature,
            "--message-text",
            "CryptoLab",
        ],
    )
    assert verified.exit_code == 0
    assert "Signature valid: True" in verified.stdout

    invalid_signature = signature[:-2] + ("00" if signature[-2:] != "00" else "01")
    invalid = runner.invoke(
        app,
        [
            "public-key",
            "rsa",
            "applied",
            "pss-verify",
            "--public-key-file",
            str(public_path),
            "--signature-hex",
            invalid_signature,
            "--message-text",
            "CryptoLab",
        ],
    )
    assert invalid.exit_code == 4
    assert "verification failed" in invalid.stderr


def test_applied_rsa_cli_output_and_input_validation(tmp_path: Path) -> None:
    same_path = tmp_path / "same.pem"
    same = runner.invoke(
        app,
        [
            "public-key",
            "rsa",
            "applied",
            "generate",
            "--private-key-out",
            str(same_path),
            "--public-key-out",
            str(same_path),
        ],
    )
    assert same.exit_code == 6
    assert "must differ" in same.stderr

    invalid_key_size = runner.invoke(
        app,
        [
            "public-key",
            "rsa",
            "applied",
            "generate",
            "--private-key-out",
            str(tmp_path / "private.pem"),
            "--public-key-out",
            str(tmp_path / "public.pem"),
            "--key-size",
            "1024",
        ],
    )
    assert invalid_key_size.exit_code == 3
    assert "2048, 3072, 4096" in invalid_key_size.stderr

    invalid_educational = runner.invoke(
        app,
        ["public-key", "rsa", "educational", "inspect", "60", "53", "17"],
    )
    assert invalid_educational.exit_code == 3
    assert "p must be prime" in invalid_educational.stderr


def test_rsa_comparison_cli() -> None:
    result = runner.invoke(app, ["--explain", "public-key", "rsa", "compare"])
    assert result.exit_code == 0
    assert "Textbook RSA" in result.stdout
    assert "Hybrid encryption" in result.stdout
