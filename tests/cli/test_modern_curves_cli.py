from __future__ import annotations

from json import loads
from pathlib import Path

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()

ALICE_PRIVATE = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
BOB_PRIVATE = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
ED_PRIVATE = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
ED_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
ED_SIGNATURE = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def test_x25519_help_exchange_and_comparison() -> None:
    help_result = runner.invoke(app, ["public-key", "x25519", "--help"])
    assert help_result.exit_code == 0
    assert "generate" in help_result.stdout
    assert "exchange" in help_result.stdout

    exchange = runner.invoke(
        app,
        [
            "--format",
            "json",
            "public-key",
            "x25519",
            "exchange",
            "--alice-private-key-hex",
            ALICE_PRIVATE,
            "--bob-private-key-hex",
            BOB_PRIVATE,
        ],
    )
    assert exchange.exit_code == 0
    payload = loads(exchange.stdout)
    assert payload["result"]["alice_shared_secret_hex"] == SHARED
    assert payload["result"]["shared_secret_matches"] is True

    comparison = runner.invoke(app, ["--format", "json", "public-key", "compare-key-agreement"])
    assert comparison.exit_code == 0
    comparison_payload = loads(comparison.stdout)
    assert [item["construction"] for item in comparison_payload["result"]] == [
        "Finite-field Diffie-Hellman",
        "X25519",
    ]


def test_x25519_key_generation_and_pem_exchange(tmp_path: Path) -> None:
    alice_private = tmp_path / "alice-private.pem"
    alice_public = tmp_path / "alice-public.pem"
    bob_private = tmp_path / "bob-private.pem"
    bob_public = tmp_path / "bob-public.pem"
    for private_path, public_path in (
        (alice_private, alice_public),
        (bob_private, bob_public),
    ):
        generated = runner.invoke(
            app,
            [
                "public-key",
                "x25519",
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

    exchanged = runner.invoke(
        app,
        [
            "public-key",
            "x25519",
            "exchange",
            "--alice-private-key-file",
            str(alice_private),
            "--bob-private-key-file",
            str(bob_private),
        ],
    )
    assert exchanged.exit_code == 0
    assert "Shared secret matches: True" in exchanged.stdout


def test_ed25519_vector_and_comparison_cli() -> None:
    signed = runner.invoke(
        app,
        [
            "public-key",
            "ed25519",
            "sign",
            "--private-key-hex",
            ED_PRIVATE,
            "--message-hex",
            "",
        ],
    )
    assert signed.exit_code == 0
    assert signed.stdout.replace("\n", "").strip() == ED_SIGNATURE

    verified = runner.invoke(
        app,
        [
            "public-key",
            "ed25519",
            "verify",
            "--public-key-hex",
            ED_PUBLIC,
            "--signature-hex",
            ED_SIGNATURE,
            "--message-hex",
            "",
        ],
    )
    assert verified.exit_code == 0
    assert "Signature valid: True" in verified.stdout

    invalid = runner.invoke(
        app,
        [
            "public-key",
            "ed25519",
            "verify",
            "--public-key-hex",
            ED_PUBLIC,
            "--signature-hex",
            ED_SIGNATURE,
            "--message-text",
            "changed",
        ],
    )
    assert invalid.exit_code == 4
    assert "verification failed" in invalid.stderr

    comparison = runner.invoke(app, ["--explain", "public-key", "compare-signatures"])
    assert comparison.exit_code == 0
    assert "RSA-PSS" in comparison.stdout
    assert "Ed25519" in comparison.stdout
    assert "HMAC-SHA-256" in comparison.stdout


def test_ed25519_key_generation_and_pem_round_trip(tmp_path: Path) -> None:
    private_path = tmp_path / "ed-private.pem"
    public_path = tmp_path / "ed-public.pem"
    generated = runner.invoke(
        app,
        [
            "public-key",
            "ed25519",
            "generate",
            "--private-key-out",
            str(private_path),
            "--public-key-out",
            str(public_path),
        ],
    )
    assert generated.exit_code == 0
    signature = runner.invoke(
        app,
        [
            "public-key",
            "ed25519",
            "sign",
            "--private-key-file",
            str(private_path),
            "--message-text",
            "CryptoLab",
        ],
    )
    assert signature.exit_code == 0
    verified = runner.invoke(
        app,
        [
            "public-key",
            "ed25519",
            "verify",
            "--public-key-file",
            str(public_path),
            "--signature-hex",
            signature.stdout.replace("\n", "").strip(),
            "--message-text",
            "CryptoLab",
        ],
    )
    assert verified.exit_code == 0


def test_modern_curve_cli_input_validation() -> None:
    missing = runner.invoke(app, ["public-key", "x25519", "exchange"])
    assert missing.exit_code == 3
    assert "Select exactly one source" in missing.stderr

    short = runner.invoke(
        app,
        [
            "public-key",
            "ed25519",
            "sign",
            "--private-key-hex",
            "00",
            "--message-text",
            "message",
        ],
    )
    assert short.exit_code == 3
    assert "exactly 32 bytes" in short.stderr
