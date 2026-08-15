"""OpenSSL 3.5 EVP-backed support shared by standardized PQC primitives."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptolab.exceptions import InputValidationError

MINIMUM_OPENSSL_VERSION = (3, 5, 0)
USER_LOCAL_OPENSSL_RELATIVE = Path("cryptolab/openssl/current/bin/openssl")
MAX_SIGNATURE_CONTEXT_BYTES = 255
EXPECTED_ML_KEM = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
EXPECTED_ML_DSA = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
EXPECTED_SLH_DSA = (
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s",
    "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s",
    "SLH-DSA-SHAKE-256f",
)


@dataclass(frozen=True, slots=True)
class OpenSSLPQCStatus:
    """Detected OpenSSL executable, version, and standardized PQC availability."""

    executable: str
    version_text: str
    version: tuple[int, int, int]
    minimum_version: str
    ml_kem: tuple[str, ...]
    ml_dsa: tuple[str, ...]
    slh_dsa: tuple[str, ...]
    ready: bool


@dataclass(frozen=True, slots=True)
class OpenSSLKeyPairMaterial:
    """Serialized key pair and public metadata returned by OpenSSL."""

    algorithm: str
    standard: str
    private_pem: bytes
    public_pem: bytes
    public_fingerprint_sha256: str
    private_format: str
    public_format: str
    private_encrypted: bool
    library: str


def _resolve_one_executable(candidate: str) -> str | None:
    expanded = str(Path(candidate).expanduser())
    if os.sep in expanded:
        path = Path(expanded)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
        return None
    return shutil.which(expanded)


def _user_local_openssl() -> Path:
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return data_home / USER_LOCAL_OPENSSL_RELATIVE


def _resolve_executable(executable: str | None = None) -> str:
    if executable is not None:
        resolved = _resolve_one_executable(executable)
        if resolved is None:
            raise InputValidationError(f"OpenSSL executable was not found: {executable}.")
        return resolved

    environment_override = os.environ.get("CRYPTOLAB_OPENSSL")
    if environment_override:
        resolved = _resolve_one_executable(environment_override)
        if resolved is None:
            raise InputValidationError(
                "CRYPTOLAB_OPENSSL does not identify an executable OpenSSL binary: "
                f"{environment_override}."
            )
        return resolved

    candidates = (
        str(_user_local_openssl()),
        "/opt/openssl-3.5/bin/openssl",
        "openssl",
    )
    for candidate in candidates:
        resolved = _resolve_one_executable(candidate)
        if resolved is not None:
            return resolved

    raise InputValidationError(
        "OpenSSL executable was not found. Standardized PQC commands require OpenSSL 3.5 "
        "or newer. From a source checkout, run scripts/install_pqc_backend.sh to install "
        "CryptoLab's isolated user-local backend, or set CRYPTOLAB_OPENSSL explicitly."
    )


def _run(
    arguments: list[str],
    *,
    executable: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    resolved = _resolve_executable(executable)
    completed = subprocess.run(  # noqa: S603
        [resolved, *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown OpenSSL error"
        raise InputValidationError(f"OpenSSL operation failed: {detail}")
    return completed


def _parse_version(text: str) -> tuple[int, int, int]:
    match = re.search(r"\bOpenSSL\s+(\d+)\.(\d+)\.(\d+)", text)
    if match is None:
        raise InputValidationError(f"Unable to parse OpenSSL version output: {text.strip()}")
    return tuple(int(value) for value in match.groups())  # type: ignore[return-value]


def _supported(expected: tuple[str, ...], listing: str) -> tuple[str, ...]:
    return tuple(name for name in expected if name in listing)


def openssl_pqc_status(*, executable: str | None = None) -> OpenSSLPQCStatus:
    """Return detected OpenSSL 3.5 PQC algorithm availability without requiring completeness."""

    resolved = _resolve_executable(executable)
    version_completed = _run(["version"], executable=resolved)
    version_text = version_completed.stdout.strip()
    version = _parse_version(version_text)
    if version < MINIMUM_OPENSSL_VERSION:
        return OpenSSLPQCStatus(
            executable=resolved,
            version_text=version_text,
            version=version,
            minimum_version="3.5.0",
            ml_kem=(),
            ml_dsa=(),
            slh_dsa=(),
            ready=False,
        )

    kem_listing = _run(["list", "-kem-algorithms"], executable=resolved).stdout
    signature_listing = _run(["list", "-signature-algorithms"], executable=resolved).stdout
    ml_kem = _supported(EXPECTED_ML_KEM, kem_listing)
    ml_dsa = _supported(EXPECTED_ML_DSA, signature_listing)
    slh_dsa = _supported(EXPECTED_SLH_DSA, signature_listing)
    ready = ml_kem == EXPECTED_ML_KEM and ml_dsa == EXPECTED_ML_DSA and slh_dsa == EXPECTED_SLH_DSA
    return OpenSSLPQCStatus(
        executable=resolved,
        version_text=version_text,
        version=version,
        minimum_version="3.5.0",
        ml_kem=ml_kem,
        ml_dsa=ml_dsa,
        slh_dsa=slh_dsa,
        ready=ready,
    )


def require_openssl_pqc(
    algorithm: str,
    *,
    kind: str,
    executable: str | None = None,
) -> str:
    """Require OpenSSL 3.5+ and the requested standardized algorithm."""

    status = openssl_pqc_status(executable=executable)
    if status.version < MINIMUM_OPENSSL_VERSION:
        raise InputValidationError(
            f"{algorithm} requires OpenSSL 3.5 or newer; detected {status.version_text}."
        )
    available = {
        "kem": status.ml_kem,
        "signature-ml-dsa": status.ml_dsa,
        "signature-slh-dsa": status.slh_dsa,
    }.get(kind)
    if available is None:
        raise InputValidationError(f"Unknown PQC backend algorithm kind: {kind}.")
    if algorithm not in available:
        raise InputValidationError(
            f"OpenSSL {status.version_text} does not expose the required algorithm {algorithm}."
        )
    return status.executable


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _key_text(
    key_path: Path,
    *,
    public: bool,
    executable: str,
) -> str:
    arguments = ["pkey"]
    if public:
        arguments.append("-pubin")
    arguments.extend(["-in", str(key_path), "-text", "-noout"])
    return _run(arguments, executable=executable).stdout


def validate_key_algorithm(
    pem: bytes,
    *,
    algorithm: str,
    public: bool,
    executable: str,
) -> None:
    """Parse a PEM key through OpenSSL and require the requested algorithm."""

    with TemporaryDirectory(prefix="cryptolab-pqc-key-") as temporary_directory:
        key_path = Path(temporary_directory) / "key.pem"
        _write(key_path, pem)
        first_line = _key_text(key_path, public=public, executable=executable).splitlines()[0]
    expected = f"{algorithm} {'Public' if public else 'Private'}-Key:"
    if first_line.strip() != expected:
        key_type = "public" if public else "private"
        raise InputValidationError(
            f"The supplied {key_type} key is not a {algorithm} key; OpenSSL reported "
            f"{first_line.strip()!r}."
        )


def public_fingerprint_from_pem(public_pem: bytes, *, executable: str) -> str:
    """Return SHA-256 over SubjectPublicKeyInfo DER bytes."""

    with TemporaryDirectory(prefix="cryptolab-pqc-fingerprint-") as temporary_directory:
        public_path = Path(temporary_directory) / "public.pem"
        der_path = Path(temporary_directory) / "public.der"
        _write(public_path, public_pem)
        _run(
            [
                "pkey",
                "-pubin",
                "-in",
                str(public_path),
                "-outform",
                "DER",
                "-out",
                str(der_path),
            ],
            executable=executable,
        )
        return sha256(der_path.read_bytes()).hexdigest()


def public_pem_from_private(private_pem: bytes, *, executable: str) -> bytes:
    """Derive SubjectPublicKeyInfo PEM from an unencrypted PKCS#8 private key."""

    with TemporaryDirectory(prefix="cryptolab-pqc-public-") as temporary_directory:
        private_path = Path(temporary_directory) / "private.pem"
        public_path = Path(temporary_directory) / "public.pem"
        _write(private_path, private_pem)
        _run(
            ["pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)],
            executable=executable,
        )
        return public_path.read_bytes()


def generate_key_pair(
    algorithm: str,
    *,
    standard: str,
    kind: str,
    executable: str | None = None,
) -> OpenSSLKeyPairMaterial:
    """Generate a standardized PQC key pair through OpenSSL 3.5 EVP."""

    resolved = require_openssl_pqc(algorithm, kind=kind, executable=executable)
    with TemporaryDirectory(prefix="cryptolab-pqc-keygen-") as temporary_directory:
        private_path = Path(temporary_directory) / "private.pem"
        public_path = Path(temporary_directory) / "public.pem"
        _run(
            ["genpkey", "-algorithm", algorithm, "-out", str(private_path)],
            executable=resolved,
        )
        _run(
            ["pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)],
            executable=resolved,
        )
        private_pem = private_path.read_bytes()
        public_pem = public_path.read_bytes()

    validate_key_algorithm(
        private_pem,
        algorithm=algorithm,
        public=False,
        executable=resolved,
    )
    validate_key_algorithm(public_pem, algorithm=algorithm, public=True, executable=resolved)
    return OpenSSLKeyPairMaterial(
        algorithm=algorithm,
        standard=standard,
        private_pem=private_pem,
        public_pem=public_pem,
        public_fingerprint_sha256=public_fingerprint_from_pem(
            public_pem,
            executable=resolved,
        ),
        private_format="PKCS#8 PEM (unencrypted)",
        public_format="SubjectPublicKeyInfo PEM",
        private_encrypted=False,
        library=f"{openssl_pqc_status(executable=resolved).version_text} EVP",
    )


def kem_encapsulate(
    algorithm: str,
    public_pem: bytes,
    *,
    executable: str | None = None,
) -> tuple[bytes, bytes, str]:
    """Encapsulate with a standardized ML-KEM public key."""

    resolved = require_openssl_pqc(algorithm, kind="kem", executable=executable)
    validate_key_algorithm(public_pem, algorithm=algorithm, public=True, executable=resolved)
    with TemporaryDirectory(prefix="cryptolab-pqc-encap-") as temporary_directory:
        public_path = Path(temporary_directory) / "public.pem"
        ciphertext_path = Path(temporary_directory) / "ciphertext.bin"
        secret_path = Path(temporary_directory) / "shared-secret.bin"
        _write(public_path, public_pem)
        _run(
            [
                "pkeyutl",
                "-encap",
                "-inkey",
                str(public_path),
                "-pubin",
                "-out",
                str(ciphertext_path),
                "-secret",
                str(secret_path),
            ],
            executable=resolved,
        )
        ciphertext = ciphertext_path.read_bytes()
        secret = secret_path.read_bytes()
    return ciphertext, secret, f"{openssl_pqc_status(executable=resolved).version_text} EVP"


def kem_decapsulate(
    algorithm: str,
    private_pem: bytes,
    ciphertext: bytes,
    *,
    executable: str | None = None,
) -> tuple[bytes, str]:
    """Decapsulate with a standardized ML-KEM private key."""

    resolved = require_openssl_pqc(algorithm, kind="kem", executable=executable)
    validate_key_algorithm(private_pem, algorithm=algorithm, public=False, executable=resolved)
    with TemporaryDirectory(prefix="cryptolab-pqc-decap-") as temporary_directory:
        private_path = Path(temporary_directory) / "private.pem"
        ciphertext_path = Path(temporary_directory) / "ciphertext.bin"
        secret_path = Path(temporary_directory) / "shared-secret.bin"
        _write(private_path, private_pem)
        _write(ciphertext_path, ciphertext)
        _run(
            [
                "pkeyutl",
                "-decap",
                "-inkey",
                str(private_path),
                "-in",
                str(ciphertext_path),
                "-secret",
                str(secret_path),
            ],
            executable=resolved,
        )
        secret = secret_path.read_bytes()
    return secret, f"{openssl_pqc_status(executable=resolved).version_text} EVP"


def sign_message(
    algorithm: str,
    private_pem: bytes,
    message: bytes,
    *,
    context: bytes,
    kind: str,
    executable: str | None = None,
) -> tuple[bytes, str, str]:
    """Sign a raw message with ML-DSA or SLH-DSA."""

    if len(context) > MAX_SIGNATURE_CONTEXT_BYTES:
        raise InputValidationError("PQC signature context must not exceed 255 bytes.")
    resolved = require_openssl_pqc(algorithm, kind=kind, executable=executable)
    validate_key_algorithm(private_pem, algorithm=algorithm, public=False, executable=resolved)
    public_pem = public_pem_from_private(private_pem, executable=resolved)
    fingerprint = public_fingerprint_from_pem(public_pem, executable=resolved)
    with TemporaryDirectory(prefix="cryptolab-pqc-sign-") as temporary_directory:
        private_path = Path(temporary_directory) / "private.pem"
        message_path = Path(temporary_directory) / "message.bin"
        signature_path = Path(temporary_directory) / "signature.bin"
        _write(private_path, private_pem)
        _write(message_path, message)
        arguments = [
            "pkeyutl",
            "-sign",
            "-in",
            str(message_path),
            "-inkey",
            str(private_path),
            "-out",
            str(signature_path),
        ]
        if context:
            arguments.extend(["-pkeyopt", f"hexcontext-string:{context.hex()}"])
        _run(arguments, executable=resolved)
        signature = signature_path.read_bytes()
    library = f"{openssl_pqc_status(executable=resolved).version_text} EVP"
    return signature, fingerprint, library


def verify_message(
    algorithm: str,
    public_pem: bytes,
    message: bytes,
    signature: bytes,
    *,
    context: bytes,
    kind: str,
    executable: str | None = None,
) -> tuple[bool, str]:
    """Verify an ML-DSA or SLH-DSA signature through OpenSSL."""

    if len(context) > MAX_SIGNATURE_CONTEXT_BYTES:
        raise InputValidationError("PQC signature context must not exceed 255 bytes.")
    resolved = require_openssl_pqc(algorithm, kind=kind, executable=executable)
    validate_key_algorithm(public_pem, algorithm=algorithm, public=True, executable=resolved)
    with TemporaryDirectory(prefix="cryptolab-pqc-verify-") as temporary_directory:
        public_path = Path(temporary_directory) / "public.pem"
        message_path = Path(temporary_directory) / "message.bin"
        signature_path = Path(temporary_directory) / "signature.bin"
        _write(public_path, public_pem)
        _write(message_path, message)
        _write(signature_path, signature)
        arguments = [
            "pkeyutl",
            "-verify",
            "-in",
            str(message_path),
            "-inkey",
            str(public_path),
            "-pubin",
            "-sigfile",
            str(signature_path),
        ]
        if context:
            arguments.extend(["-pkeyopt", f"hexcontext-string:{context.hex()}"])
        completed = _run(arguments, executable=resolved, check=False)
    library = f"{openssl_pqc_status(executable=resolved).version_text} EVP"
    if completed.returncode == 0:
        return True, library
    verification_text = (completed.stdout + completed.stderr).lower()
    if (
        "signature verification failure" in verification_text
        or "bad signature" in verification_text
    ):
        return False, library
    if completed.returncode == 1:
        return False, library
    detail = completed.stderr.strip() or completed.stdout.strip() or "unknown OpenSSL error"
    raise InputValidationError(f"OpenSSL verification operation failed: {detail}")
