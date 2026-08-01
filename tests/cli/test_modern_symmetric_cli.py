from __future__ import annotations

from json import loads

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()
AES_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
BLOCK = "6bc1bee22e409f96e93d7e117393172a"


def test_symmetric_help_lists_modern_commands() -> None:
    result = runner.invoke(app, ["symmetric", "--help"])
    assert result.exit_code == 0
    assert "aes" in result.stdout
    assert "chacha20-poly1305" in result.stdout
    assert "compare-aead" in result.stdout


def test_aes_ecb_vector_and_mode_comparison() -> None:
    encrypted = runner.invoke(
        app,
        [
            "symmetric",
            "aes",
            "encrypt",
            "ecb",
            "--key-hex",
            AES_KEY,
            "--plaintext-hex",
            BLOCK,
        ],
    )
    assert encrypted.exit_code == 0
    assert encrypted.stdout.strip() == "3ad77bb40d7a3660a89ecaf32466ef97"

    comparison = runner.invoke(app, ["symmetric", "aes", "compare-modes"])
    assert comparison.exit_code == 0
    assert "CFB-128" in comparison.stdout
    assert "XTS" in comparison.stdout


def test_aes_cbc_pkcs7_cli_round_trip() -> None:
    encrypted = runner.invoke(
        app,
        [
            "--format",
            "json",
            "symmetric",
            "aes",
            "encrypt",
            "cbc",
            "--key-hex",
            AES_KEY,
            "--plaintext-text",
            "CryptoLab",
            "--padding",
            "pkcs7",
            "--iv-hex",
            "000102030405060708090a0b0c0d0e0f",
        ],
    )
    assert encrypted.exit_code == 0
    ciphertext = loads(encrypted.stdout)["result"]["output_hex"]
    decrypted = runner.invoke(
        app,
        [
            "--format",
            "json",
            "symmetric",
            "aes",
            "decrypt",
            "cbc",
            "--key-hex",
            AES_KEY,
            "--ciphertext-hex",
            ciphertext,
            "--padding",
            "pkcs7",
            "--iv-hex",
            "000102030405060708090a0b0c0d0e0f",
        ],
    )
    assert decrypted.exit_code == 0
    assert bytes.fromhex(loads(decrypted.stdout)["result"]["output_hex"]) == b"CryptoLab"


def test_aes_gcm_cli_and_invalid_tag() -> None:
    encrypted = runner.invoke(
        app,
        [
            "--format",
            "json",
            "symmetric",
            "aes",
            "encrypt",
            "gcm",
            "--key-hex",
            "00" * 16,
            "--plaintext-hex",
            "00" * 16,
            "--nonce-hex",
            "00" * 12,
            "--aad-text",
            "header",
        ],
    )
    assert encrypted.exit_code == 0
    payload = loads(encrypted.stdout)
    decrypted = runner.invoke(
        app,
        [
            "symmetric",
            "aes",
            "decrypt",
            "gcm",
            "--key-hex",
            "00" * 16,
            "--ciphertext-hex",
            payload["result"]["output_hex"],
            "--nonce-hex",
            "00" * 12,
            "--tag-hex",
            payload["result"]["tag_hex"],
            "--aad-text",
            "header",
        ],
    )
    assert decrypted.exit_code == 0
    assert decrypted.stdout.strip() == "00" * 16

    invalid = runner.invoke(
        app,
        [
            "symmetric",
            "aes",
            "decrypt",
            "gcm",
            "--key-hex",
            "00" * 16,
            "--ciphertext-hex",
            payload["result"]["output_hex"],
            "--nonce-hex",
            "00" * 12,
            "--tag-hex",
            "00" * 16,
            "--aad-text",
            "header",
        ],
    )
    assert invalid.exit_code == 4
    assert "authentication failed" in invalid.stderr


def test_chacha20_poly1305_cli_round_trip_and_comparison() -> None:
    encrypted = runner.invoke(
        app,
        [
            "--format",
            "json",
            "symmetric",
            "chacha20-poly1305",
            "encrypt",
            "--key-hex",
            "00" * 32,
            "--nonce-hex",
            "00" * 12,
            "--plaintext-text",
            "message",
            "--aad-text",
            "header",
        ],
    )
    assert encrypted.exit_code == 0
    payload = loads(encrypted.stdout)
    decrypted = runner.invoke(
        app,
        [
            "symmetric",
            "chacha20-poly1305",
            "decrypt",
            "--key-hex",
            "00" * 32,
            "--nonce-hex",
            "00" * 12,
            "--ciphertext-hex",
            payload["result"]["output_hex"],
            "--tag-hex",
            payload["result"]["tag_hex"],
            "--aad-text",
            "header",
        ],
    )
    assert decrypted.exit_code == 0
    assert bytes.fromhex(decrypted.stdout.strip()) == b"message"

    comparison = runner.invoke(app, ["symmetric", "compare-aead"])
    assert comparison.exit_code == 0
    assert "AES-GCM" in comparison.stdout
    assert "ChaCha20-Poly1305" in comparison.stdout


def test_modern_symmetric_cli_validation_errors() -> None:
    missing_source = runner.invoke(
        app,
        ["symmetric", "aes", "encrypt", "ecb", "--key-hex", AES_KEY],
    )
    assert missing_source.exit_code == 3
    assert "exactly one source for plaintext" in missing_source.stderr

    irrelevant_parameter = runner.invoke(
        app,
        [
            "symmetric",
            "aes",
            "encrypt",
            "ecb",
            "--key-hex",
            AES_KEY,
            "--plaintext-hex",
            BLOCK,
            "--iv-hex",
            "00" * 16,
        ],
    )
    assert irrelevant_parameter.exit_code == 3
    assert "IV is not used" in irrelevant_parameter.stderr
