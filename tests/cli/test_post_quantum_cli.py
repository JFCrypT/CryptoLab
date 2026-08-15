from __future__ import annotations

from json import loads
from pathlib import Path

from typer.testing import CliRunner

from cryptolab.cli.app import app

runner = CliRunner()


def test_post_quantum_help_foundations_parameters_and_comparisons() -> None:
    help_result = runner.invoke(app, ["post-quantum", "--help"])
    assert help_result.exit_code == 0
    for command in ("foundations", "ml-kem", "ml-dsa", "slh-dsa", "overview"):
        assert command in help_result.stdout

    ring = runner.invoke(
        app,
        ["--format", "json", "post-quantum", "foundations", "ring-multiply", "17", "1,2", "3,4"],
    )
    assert ring.exit_code == 0
    assert loads(ring.stdout)["result"]["coefficients"] == [12, 10]

    lwe = runner.invoke(
        app,
        [
            "--explain",
            "post-quantum",
            "foundations",
            "lwe-example",
            "17",
            "--row",
            "1,2",
            "--secret",
            "3,4",
            "--error",
            "1",
        ],
    )
    assert lwe.exit_code == 0
    assert "b = A*s + e" in lwe.stdout

    for group, expected in (
        ("ml-kem", "ML-KEM-1024"),
        ("ml-dsa", "ML-DSA-87"),
        ("slh-dsa", "SLH-DSA-SHAKE-256f"),
    ):
        result = runner.invoke(app, ["post-quantum", group, "parameters"])
        assert result.exit_code == 0
        assert expected in result.stdout

    establishment = runner.invoke(app, ["post-quantum", "compare-key-establishment"])
    assert establishment.exit_code == 0
    assert "X25519" in establishment.stdout
    assert "ML-KEM" in establishment.stdout
    signatures = runner.invoke(app, ["post-quantum", "compare-signatures"])
    assert signatures.exit_code == 0
    assert "RSA-PSS" in signatures.stdout
    assert "SLH-DSA" in signatures.stdout
    overview = runner.invoke(app, ["--format", "json", "post-quantum", "overview"])
    assert overview.exit_code == 0
    assert len(loads(overview.stdout)["result"]) == 6


def test_post_quantum_cli_validation_without_backend(tmp_path: Path) -> None:
    invalid_vector = runner.invoke(
        app,
        ["post-quantum", "foundations", "ring-multiply", "17", "1,,2", "3,4,5"],
    )
    assert invalid_vector.exit_code == 3
    assert "comma-separated integers" in invalid_vector.stderr

    missing_ciphertext = runner.invoke(
        app,
        [
            "post-quantum",
            "ml-kem",
            "decapsulate",
            "ML-KEM-512",
            "--private-key-file",
            str(tmp_path / "missing.pem"),
        ],
    )
    assert missing_ciphertext.exit_code in {3, 6}

    missing_message = runner.invoke(
        app,
        [
            "post-quantum",
            "ml-dsa",
            "sign",
            "ML-DSA-44",
            "--private-key-file",
            str(tmp_path / "missing.pem"),
        ],
    )
    assert missing_message.exit_code == 3
    assert "Select exactly one source for message" in missing_message.stderr


def test_root_help_includes_post_quantum() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "post-quantum" in result.stdout
