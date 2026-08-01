from __future__ import annotations

from json import loads
from pathlib import Path

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hashing_help_lists_required_commands() -> None:
    result = runner.invoke(app, ["hashing", "--help"])
    assert result.exit_code == 0
    assert "digest" in result.stdout
    assert "avalanche" in result.stdout
    assert "hmac-sha256" in result.stdout
    assert "hkdf-sha256" in result.stdout


def test_digest_text_hex_and_file(tmp_path: Path) -> None:
    text = runner.invoke(app, ["hashing", "digest", "sha256", "--message-text", "abc"])
    assert text.exit_code == 0
    assert text.stdout.strip() == SHA256_ABC

    hexadecimal = runner.invoke(
        app,
        ["hashing", "digest", "sha3-256", "--message-hex", "616263"],
    )
    assert hexadecimal.exit_code == 0
    assert hexadecimal.stdout.strip().startswith("3a985da7")

    path = tmp_path / "message.bin"
    path.write_bytes(b"abc")
    file_result = runner.invoke(
        app,
        ["--format", "json", "hashing", "digest", "sha256", "--message-file", str(path)],
    )
    assert file_result.exit_code == 0
    payload = loads(file_result.stdout)
    assert payload["result"]["digest_hex"] == SHA256_ABC
    assert payload["inputs"]["source_kind"] == "file"


def test_digest_verification_success_and_failure() -> None:
    valid = runner.invoke(
        app,
        [
            "hashing",
            "verify",
            "sha256",
            "--digest-hex",
            SHA256_ABC,
            "--message-text",
            "abc",
        ],
    )
    assert valid.exit_code == 0
    assert "Digest valid: True" in valid.stdout

    invalid = runner.invoke(
        app,
        [
            "hashing",
            "verify",
            "sha256",
            "--digest-hex",
            "00" * 32,
            "--message-text",
            "abc",
        ],
    )
    assert invalid.exit_code == 4
    assert "verification failed" in invalid.stderr


def test_avalanche_and_comparison_commands() -> None:
    avalanche = runner.invoke(
        app,
        [
            "--format",
            "json",
            "--explain",
            "hashing",
            "avalanche",
            "sha256",
            "--left-text",
            "abc",
            "--right-text",
            "abd",
        ],
    )
    assert avalanche.exit_code == 0
    payload = loads(avalanche.stdout)
    assert payload["inputs"]["changed_input_bits"] == 3
    assert len(payload["trace"]) == 32

    hashes = runner.invoke(app, ["hashing", "compare-hashes"])
    assert hashes.exit_code == 0
    assert "SHA3-256" in hashes.stdout
    hash_mac = runner.invoke(app, ["hashing", "compare-hash-mac"])
    assert hash_mac.exit_code == 0
    assert "HMAC-SHA-256" in hash_mac.stdout


def test_hmac_cli_rfc_vector_and_invalid_tag() -> None:
    generated = runner.invoke(
        app,
        [
            "hashing",
            "hmac-sha256",
            "generate",
            "--key-hex",
            "0b" * 20,
            "--message-text",
            "Hi There",
        ],
    )
    assert generated.exit_code == 0
    expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    assert generated.stdout.strip() == expected

    verified = runner.invoke(
        app,
        [
            "hashing",
            "hmac-sha256",
            "verify",
            "--tag-hex",
            expected,
            "--key-hex",
            "0b" * 20,
            "--message-text",
            "Hi There",
        ],
    )
    assert verified.exit_code == 0
    assert "Tag valid: True" in verified.stdout

    invalid = runner.invoke(
        app,
        [
            "hashing",
            "hmac-sha256",
            "verify",
            "--tag-hex",
            "00" * 32,
            "--key-text",
            "key",
            "--message-text",
            "message",
        ],
    )
    assert invalid.exit_code == 4
    assert "HMAC-SHA-256 verification failed" in invalid.stderr


def test_hkdf_cli_rfc_vector_and_defaults() -> None:
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "--explain",
            "hashing",
            "hkdf-sha256",
            "derive",
            "--length",
            "42",
            "--ikm-hex",
            "0b" * 22,
            "--salt-hex",
            "000102030405060708090a0b0c",
            "--info-hex",
            "f0f1f2f3f4f5f6f7f8f9",
        ],
    )
    assert result.exit_code == 0
    payload = loads(result.stdout)
    assert payload["result"]["prk_hex"].startswith("07770936")
    assert payload["result"]["okm_hex"].startswith("3cb25f25")
    assert len(payload["trace"]) == 2

    defaults = runner.invoke(
        app,
        [
            "hashing",
            "hkdf-sha256",
            "derive",
            "--length",
            "16",
            "--ikm-text",
            "shared secret",
        ],
    )
    assert defaults.exit_code == 0
    assert "PRK:" in defaults.stdout
    assert "OKM:" in defaults.stdout


def test_hashing_cli_input_validation() -> None:
    missing = runner.invoke(app, ["hashing", "digest", "sha256"])
    assert missing.exit_code == 3
    assert "exactly one source for message" in missing.stderr

    same = runner.invoke(
        app,
        [
            "hashing",
            "avalanche",
            "sha256",
            "--left-text",
            "same",
            "--right-text",
            "same",
        ],
    )
    assert same.exit_code == 3
    assert "must differ" in same.stderr

    oversized = runner.invoke(
        app,
        [
            "hashing",
            "hkdf-sha256",
            "derive",
            "--length",
            "8161",
            "--ikm-text",
            "ikm",
        ],
    )
    assert oversized.exit_code == 3
    assert "between 1 and 8160" in oversized.stderr
