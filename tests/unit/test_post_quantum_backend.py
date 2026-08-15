from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from cryptolab.exceptions import InputValidationError
from cryptolab.post_quantum import openssl_backend as backend


def completed(
    stdout: str = "", stderr: str = "", code: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["openssl"], code, stdout, stderr)


def test_version_parsing_supported_filter_and_missing_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert backend._parse_version("OpenSSL 3.5.5 27 Jan 2026") == (3, 5, 5)
    assert backend._supported(("A", "B"), "x A y") == ("A",)
    with pytest.raises(InputValidationError, match="parse"):
        backend._parse_version("LibreSSL")
    monkeypatch.setattr(backend.shutil, "which", lambda value: None)
    with pytest.raises(InputValidationError, match="not found"):
        backend._resolve_executable("missing-openssl")


def test_run_success_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend.shutil, "which", lambda value: "/usr/bin/openssl")
    monkeypatch.setattr(
        backend.subprocess,
        "run",
        lambda *args, **kwargs: completed("ok\n"),
    )
    assert backend._run(["version"]).stdout == "ok\n"
    monkeypatch.setattr(
        backend.subprocess,
        "run",
        lambda *args, **kwargs: completed(stderr="failure", code=2),
    )
    with pytest.raises(InputValidationError, match="failure"):
        backend._run(["bad"])
    assert backend._run(["bad"], check=False).returncode == 2


def test_status_old_complete_and_require(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend, "_resolve_executable", lambda executable=None: "/mock/openssl")

    def old_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed("OpenSSL 3.4.9\n")

    monkeypatch.setattr(backend, "_run", old_run)
    old = backend.openssl_pqc_status()
    assert old.version == (3, 4, 9)
    assert not old.ready
    with pytest.raises(InputValidationError, match=r"requires OpenSSL 3\.5"):
        backend.require_openssl_pqc("ML-KEM-768", kind="kem")

    def ready_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if arguments == ["version"]:
            return completed("OpenSSL 3.5.5\n")
        if arguments == ["list", "-kem-algorithms"]:
            return completed(" ".join(backend.EXPECTED_ML_KEM))
        return completed(" ".join((*backend.EXPECTED_ML_DSA, *backend.EXPECTED_SLH_DSA)))

    monkeypatch.setattr(backend, "_run", ready_run)
    status = backend.openssl_pqc_status()
    assert status.ready
    assert backend.require_openssl_pqc("ML-KEM-768", kind="kem") == "/mock/openssl"
    with pytest.raises(InputValidationError, match="Unknown"):
        backend.require_openssl_pqc("ML-KEM-768", kind="wrong")
    with pytest.raises(InputValidationError, match="does not expose"):
        backend.require_openssl_pqc("ML-KEM-NOT-REAL", kind="kem")


def test_key_validation_fingerprint_and_public_derivation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(backend, "TemporaryDirectory", lambda **kwargs: _TempDir(tmp_path))
    monkeypatch.setattr(
        backend,
        "_key_text",
        lambda path, *, public, executable: f"ML-DSA-44 {'Public' if public else 'Private'}-Key:\n",
    )
    backend.validate_key_algorithm(
        b"pem", algorithm="ML-DSA-44", public=False, executable="openssl"
    )
    monkeypatch.setattr(
        backend,
        "_key_text",
        lambda path, *, public, executable: "RSA Public-Key:\n",
    )
    with pytest.raises(InputValidationError, match="not a ML-DSA-44"):
        backend.validate_key_algorithm(
            b"pem", algorithm="ML-DSA-44", public=True, executable="openssl"
        )

    def fake_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "DER" in arguments:
            Path(arguments[arguments.index("-out") + 1]).write_bytes(b"der")
        elif "-pubout" in arguments:
            Path(arguments[arguments.index("-out") + 1]).write_bytes(b"public")
        return completed()

    monkeypatch.setattr(backend, "_run", fake_run)
    assert (
        backend.public_fingerprint_from_pem(b"pem", executable="openssl")
        == backend.sha256(b"der").hexdigest()
    )
    assert backend.public_pem_from_private(b"private", executable="openssl") == b"public"


def test_generate_kem_and_signing_backend_operations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(backend, "TemporaryDirectory", lambda **kwargs: _TempDir(tmp_path))
    monkeypatch.setattr(backend, "require_openssl_pqc", lambda *args, **kwargs: "openssl")
    monkeypatch.setattr(backend, "validate_key_algorithm", lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, "public_fingerprint_from_pem", lambda *args, **kwargs: "f" * 64)
    monkeypatch.setattr(backend, "public_pem_from_private", lambda *args, **kwargs: b"public")
    status = backend.OpenSSLPQCStatus(
        executable="openssl",
        version_text="OpenSSL 3.5.5",
        version=(3, 5, 5),
        minimum_version="3.5.0",
        ml_kem=backend.EXPECTED_ML_KEM,
        ml_dsa=backend.EXPECTED_ML_DSA,
        slh_dsa=backend.EXPECTED_SLH_DSA,
        ready=True,
    )
    monkeypatch.setattr(backend, "openssl_pqc_status", lambda **kwargs: status)

    verification_code = 0

    def fake_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal verification_code
        if arguments and arguments[0] == "genpkey":
            Path(arguments[arguments.index("-out") + 1]).write_bytes(b"private")
        elif arguments and arguments[0] == "pkey" and "-pubout" in arguments:
            Path(arguments[arguments.index("-out") + 1]).write_bytes(b"public")
        elif "-encap" in arguments:
            Path(arguments[arguments.index("-out") + 1]).write_bytes(b"ciphertext")
            Path(arguments[arguments.index("-secret") + 1]).write_bytes(b"secret")
        elif "-decap" in arguments:
            Path(arguments[arguments.index("-secret") + 1]).write_bytes(b"secret")
        elif "-sign" in arguments:
            Path(arguments[arguments.index("-out") + 1]).write_bytes(b"signature")
        elif "-verify" in arguments:
            error_text = "signature verification failure" if verification_code == 1 else ""
            if verification_code == 2:
                error_text = "backend failure"
            return completed("", error_text, verification_code)
        return completed()

    monkeypatch.setattr(backend, "_run", fake_run)
    material = backend.generate_key_pair(
        "ML-KEM-768", standard="FIPS 203", kind="kem", executable="openssl"
    )
    assert material.private_pem == b"private"
    assert material.public_pem == b"public"
    assert material.library == "OpenSSL 3.5.5 EVP"

    ciphertext, secret, library = backend.kem_encapsulate(
        "ML-KEM-768", b"public", executable="openssl"
    )
    assert (ciphertext, secret, library) == (b"ciphertext", b"secret", "OpenSSL 3.5.5 EVP")
    assert backend.kem_decapsulate(
        "ML-KEM-768", b"private", b"ciphertext", executable="openssl"
    ) == (b"secret", "OpenSSL 3.5.5 EVP")

    signature, fingerprint, sign_library = backend.sign_message(
        "ML-DSA-44",
        b"private",
        b"message",
        context=b"ctx",
        kind="signature-ml-dsa",
        executable="openssl",
    )
    assert signature == b"signature"
    assert fingerprint == "f" * 64
    assert sign_library == "OpenSSL 3.5.5 EVP"
    assert backend.verify_message(
        "ML-DSA-44",
        b"public",
        b"message",
        signature,
        context=b"ctx",
        kind="signature-ml-dsa",
        executable="openssl",
    ) == (True, "OpenSSL 3.5.5 EVP")
    verification_code = 1
    assert backend.verify_message(
        "ML-DSA-44",
        b"public",
        b"message",
        signature,
        context=b"",
        kind="signature-ml-dsa",
        executable="openssl",
    ) == (False, "OpenSSL 3.5.5 EVP")
    verification_code = 2
    with pytest.raises(InputValidationError, match="verification operation failed"):
        backend.verify_message(
            "ML-DSA-44",
            b"public",
            b"message",
            signature,
            context=b"",
            kind="signature-ml-dsa",
            executable="openssl",
        )


def test_signature_context_limit() -> None:
    too_long = b"x" * (backend.MAX_SIGNATURE_CONTEXT_BYTES + 1)
    with pytest.raises(InputValidationError, match="255"):
        backend.sign_message("ML-DSA-44", b"key", b"m", context=too_long, kind="signature-ml-dsa")
    with pytest.raises(InputValidationError, match="255"):
        backend.verify_message(
            "ML-DSA-44", b"key", b"m", b"sig", context=too_long, kind="signature-ml-dsa"
        )


class _TempDir:
    def __init__(self, path: Path) -> None:
        self.path = path

    def __enter__(self) -> str:
        self.path.mkdir(parents=True, exist_ok=True)
        return str(self.path)

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        for path in self.path.iterdir():
            if path.is_file():
                path.unlink()


def test_runtime_discovery_prefers_environment_then_user_local(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    environment_openssl = tmp_path / "environment-openssl"
    environment_openssl.write_text("#!/bin/sh\n", encoding="utf-8")
    environment_openssl.chmod(0o755)
    monkeypatch.setenv("CRYPTOLAB_OPENSSL", str(environment_openssl))
    assert backend._resolve_executable() == str(environment_openssl.resolve())

    monkeypatch.delenv("CRYPTOLAB_OPENSSL")
    data_home = tmp_path / "data"
    managed_openssl = data_home / "cryptolab/openssl/current/bin/openssl"
    managed_openssl.parent.mkdir(parents=True)
    managed_openssl.write_text("#!/bin/sh\n", encoding="utf-8")
    managed_openssl.chmod(0o755)
    monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
    monkeypatch.setattr(backend.shutil, "which", lambda value: "/usr/bin/openssl")
    assert backend._resolve_executable() == str(managed_openssl.resolve())


def test_invalid_environment_override_does_not_silently_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CRYPTOLAB_OPENSSL", "/does/not/exist/openssl")
    with pytest.raises(InputValidationError, match="CRYPTOLAB_OPENSSL"):
        backend._resolve_executable()
