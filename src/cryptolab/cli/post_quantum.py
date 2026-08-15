"""CLI commands for post-quantum foundations and standardized PQC primitives."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from cryptolab.cli.common import execute
from cryptolab.encoding import ByteInput, parse_hex_bytes, read_byte_source
from cryptolab.exceptions import (
    CryptoLabError,
    InputError,
    InputValidationError,
    OutputError,
    VerificationError,
)
from cryptolab.post_quantum.comparisons import (
    classical_post_quantum_profiles,
    post_quantum_key_establishment_profiles,
    post_quantum_signature_profiles,
)
from cryptolab.post_quantum.foundations import negacyclic_multiply, toy_lwe_sample
from cryptolab.post_quantum.ml_dsa import (
    MLDSAParameterSet,
    generate_ml_dsa_key_pair,
    ml_dsa_parameter_profiles,
    ml_dsa_sign,
    ml_dsa_verify,
)
from cryptolab.post_quantum.ml_kem import (
    MLKEMParameterSet,
    generate_ml_kem_key_pair,
    ml_kem_decapsulate,
    ml_kem_encapsulate,
    ml_kem_parameter_profiles,
)
from cryptolab.post_quantum.openssl_backend import (
    MAX_SIGNATURE_CONTEXT_BYTES,
    openssl_pqc_status,
)
from cryptolab.post_quantum.slh_dsa import (
    SLHDSAParameterSet,
    generate_slh_dsa_key_pair,
    slh_dsa_parameter_profiles,
    slh_dsa_sign,
    slh_dsa_verify,
)
from cryptolab.rendering.post_quantum import (
    MLDSAParametersView,
    MLKEMDecapsulationView,
    MLKEMEncapsulationView,
    MLKEMParametersView,
    NegacyclicMultiplicationView,
    OpenSSLPQCStatusView,
    PQCComparisonView,
    PQCKeyGenerationView,
    PQCSignatureView,
    PQCVerificationView,
    SLHDSAParametersView,
    ToyLWEView,
)

if TYPE_CHECKING:
    from cryptolab.rendering.common import SupportsRender


app = typer.Typer(
    name="post-quantum",
    help="Study standardized post-quantum cryptography and bounded educational foundations.",
    no_args_is_help=True,
)
foundations_app = typer.Typer(
    name="foundations",
    help="Inspect tiny polynomial-ring and LWE-style examples; never use them as cryptography.",
    no_args_is_help=True,
)
ml_kem_app = typer.Typer(
    name="ml-kem",
    help="Use FIPS 203 ML-KEM through the OpenSSL 3.5+ EVP provider.",
    no_args_is_help=True,
)
ml_dsa_app = typer.Typer(
    name="ml-dsa",
    help="Use FIPS 204 ML-DSA through the OpenSSL 3.5+ EVP provider.",
    no_args_is_help=True,
)
slh_dsa_app = typer.Typer(
    name="slh-dsa",
    help="Use FIPS 205 SLH-DSA through the OpenSSL 3.5+ EVP provider.",
    no_args_is_help=True,
)


def _run(context: typer.Context, factory: Callable[[], SupportsRender]) -> None:
    try:
        execute(context, factory())
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


def _parse_integer_vector(value: str, *, label: str) -> tuple[int, ...]:
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part for part in parts):
        raise InputValidationError(f"{label.capitalize()} must be comma-separated integers.")
    try:
        return tuple(int(part, 10) for part in parts)
    except ValueError as error:
        raise InputValidationError(
            f"{label.capitalize()} must be comma-separated integers."
        ) from error


def _read_file(path: Path, *, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise InputError(f"Unable to read {label} file: {path}") from error


def _read_hex_or_file(
    *,
    label: str,
    hex_value: str | None,
    file: Path | None,
) -> ByteInput:
    if (hex_value is None) == (file is None):
        raise InputValidationError(
            f"Select exactly one source for {label}: --{label}-hex or --{label}-file."
        )
    return read_byte_source(label=label, text=None, hex_value=hex_value, file=file)


def _context_bytes(context_text: str | None, context_hex: str | None) -> bytes:
    if context_text is not None and context_hex is not None:
        raise InputValidationError("Select at most one signature context: text or hexadecimal.")
    if context_text is not None:
        context = context_text.encode("utf-8", errors="strict")
    elif context_hex is not None:
        context = parse_hex_bytes(context_hex, label="signature context")
    else:
        context = b""
    if len(context) > MAX_SIGNATURE_CONTEXT_BYTES:
        raise InputValidationError(
            f"PQC signature context must not exceed {MAX_SIGNATURE_CONTEXT_BYTES} bytes."
        )
    return context


def _validate_output_path(path: Path, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise OutputError(f"Output file already exists: {path}; use --overwrite to replace it.")


def _validate_key_output_paths(private_path: Path, public_path: Path, *, overwrite: bool) -> None:
    if private_path.absolute() == public_path.absolute():
        raise OutputError("Private-key and public-key output paths must differ.")
    _validate_output_path(private_path, overwrite=overwrite)
    _validate_output_path(public_path, overwrite=overwrite)


def _write_atomic_bytes(path: Path, data: bytes, *, mode: int, overwrite: bool) -> None:
    _validate_output_path(path, overwrite=overwrite)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary.write(data)
            temporary_path = Path(temporary.name)
        temporary_path.chmod(mode)
        temporary_path.replace(path)
    except OSError as error:
        raise OutputError(f"Unable to write output file: {path}") from error


def _write_key_pair(
    private_path: Path,
    public_path: Path,
    *,
    private_pem: bytes,
    public_pem: bytes,
    overwrite: bool,
) -> None:
    _validate_key_output_paths(private_path, public_path, overwrite=overwrite)
    _write_atomic_bytes(private_path, private_pem, mode=0o600, overwrite=overwrite)
    _write_atomic_bytes(public_path, public_pem, mode=0o644, overwrite=overwrite)


@app.command("backend")
def backend_command(context: typer.Context) -> None:
    """Inspect the OpenSSL 3.5+ PQC backend and standardized algorithm availability."""

    _run(context, lambda: OpenSSLPQCStatusView(openssl_pqc_status()))


@foundations_app.command("ring-multiply")
def ring_multiply_command(
    context: typer.Context,
    modulus: Annotated[int, typer.Argument(help="Small educational modulus q.")],
    left: Annotated[str, typer.Argument(help="Comma-separated coefficients a_0,...,a_(n-1).")],
    right: Annotated[str, typer.Argument(help="Comma-separated coefficients b_0,...,b_(n-1).")],
) -> None:
    """Multiply in the tiny ring Z_q[x]/(x^n + 1)."""

    _run(
        context,
        lambda: NegacyclicMultiplicationView(
            negacyclic_multiply(
                _parse_integer_vector(left, label="left polynomial"),
                _parse_integer_vector(right, label="right polynomial"),
                modulus=modulus,
            )
        ),
    )


@foundations_app.command("lwe-example")
def lwe_example_command(
    context: typer.Context,
    modulus: Annotated[int, typer.Argument(help="Small educational modulus q.")],
    row: Annotated[
        list[str],
        typer.Option("--row", help="One comma-separated matrix row; repeat for each row."),
    ],
    secret: Annotated[str, typer.Option("--secret", help="Comma-separated secret vector.")],
    error: Annotated[str, typer.Option("--error", help="Comma-separated small error vector.")],
) -> None:
    """Compute a tiny LWE-style b = A*s + e mod q example."""

    def factory() -> ToyLWEView:
        matrix = tuple(_parse_integer_vector(value, label="matrix row") for value in row)
        return ToyLWEView(
            toy_lwe_sample(
                matrix,
                _parse_integer_vector(secret, label="secret vector"),
                _parse_integer_vector(error, label="error vector"),
                modulus=modulus,
            )
        )

    _run(context, factory)


@ml_kem_app.command("parameters")
def ml_kem_parameters_command(context: typer.Context) -> None:
    """List the three FIPS 203 parameter sets and raw standardized sizes."""

    _run(context, lambda: MLKEMParametersView(ml_kem_parameter_profiles()))


@ml_kem_app.command("generate")
def ml_kem_generate_command(
    context: typer.Context,
    parameter_set: Annotated[MLKEMParameterSet, typer.Argument(help="FIPS 203 parameter set.")],
    private_key_out: Annotated[
        Path,
        typer.Option("--private-key-out", help="Write unencrypted PKCS#8 PEM here."),
    ],
    public_key_out: Annotated[
        Path,
        typer.Option("--public-key-out", help="Write SubjectPublicKeyInfo PEM here."),
    ],
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Replace existing output files explicitly."),
    ] = False,
) -> None:
    """Generate an ML-KEM key pair through OpenSSL 3.5+ EVP."""

    def factory() -> PQCKeyGenerationView:
        result = generate_ml_kem_key_pair(parameter_set)
        _write_key_pair(
            private_key_out,
            public_key_out,
            private_pem=result.private_pem,
            public_pem=result.public_pem,
            overwrite=overwrite,
        )
        return PQCKeyGenerationView(result, str(private_key_out), str(public_key_out))

    _run(context, factory)


@ml_kem_app.command("encapsulate")
def ml_kem_encapsulate_command(
    context: typer.Context,
    parameter_set: Annotated[MLKEMParameterSet, typer.Argument(help="FIPS 203 parameter set.")],
    public_key_file: Annotated[
        Path,
        typer.Option("--public-key-file", help="ML-KEM SubjectPublicKeyInfo PEM key."),
    ],
    ciphertext_out: Annotated[
        Path | None,
        typer.Option("--ciphertext-out", help="Optionally write binary ciphertext here."),
    ] = None,
    shared_secret_out: Annotated[
        Path | None,
        typer.Option("--shared-secret-out", help="Optionally write the 32-byte secret here."),
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Replace existing output files explicitly."),
    ] = False,
) -> None:
    """Encapsulate a fresh 32-byte shared secret with ML-KEM."""

    def factory() -> MLKEMEncapsulationView:
        result = ml_kem_encapsulate(
            parameter_set,
            _read_file(public_key_file, label="ML-KEM public key"),
        )
        if ciphertext_out is not None:
            _write_atomic_bytes(
                ciphertext_out,
                bytes.fromhex(result.ciphertext_hex),
                mode=0o644,
                overwrite=overwrite,
            )
        if shared_secret_out is not None:
            _write_atomic_bytes(
                shared_secret_out,
                bytes.fromhex(result.shared_secret_hex),
                mode=0o600,
                overwrite=overwrite,
            )
        return MLKEMEncapsulationView(
            result,
            None if ciphertext_out is None else str(ciphertext_out),
            None if shared_secret_out is None else str(shared_secret_out),
        )

    _run(context, factory)


@ml_kem_app.command("decapsulate")
def ml_kem_decapsulate_command(
    context: typer.Context,
    parameter_set: Annotated[MLKEMParameterSet, typer.Argument(help="FIPS 203 parameter set.")],
    private_key_file: Annotated[
        Path,
        typer.Option("--private-key-file", help="Unencrypted ML-KEM PKCS#8 PEM key."),
    ],
    ciphertext_hex: Annotated[
        str | None,
        typer.Option("--ciphertext-hex", help="Ciphertext as canonical hexadecimal bytes."),
    ] = None,
    ciphertext_file: Annotated[
        Path | None,
        typer.Option("--ciphertext-file", help="Read binary ciphertext from this file."),
    ] = None,
    shared_secret_out: Annotated[
        Path | None,
        typer.Option("--shared-secret-out", help="Optionally write the recovered secret here."),
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Replace an existing shared-secret file explicitly."),
    ] = False,
) -> None:
    """Decapsulate an ML-KEM ciphertext with the matching private key."""

    def factory() -> MLKEMDecapsulationView:
        ciphertext = _read_hex_or_file(
            label="ciphertext",
            hex_value=ciphertext_hex,
            file=ciphertext_file,
        )
        result = ml_kem_decapsulate(
            parameter_set,
            _read_file(private_key_file, label="ML-KEM private key"),
            ciphertext.data,
        )
        if shared_secret_out is not None:
            _write_atomic_bytes(
                shared_secret_out,
                bytes.fromhex(result.shared_secret_hex),
                mode=0o600,
                overwrite=overwrite,
            )
        return MLKEMDecapsulationView(
            result,
            None if shared_secret_out is None else str(shared_secret_out),
        )

    _run(context, factory)


@ml_dsa_app.command("parameters")
def ml_dsa_parameters_command(context: typer.Context) -> None:
    """List the three FIPS 204 parameter sets and raw standardized sizes."""

    _run(context, lambda: MLDSAParametersView(ml_dsa_parameter_profiles()))


@ml_dsa_app.command("generate")
def ml_dsa_generate_command(
    context: typer.Context,
    parameter_set: Annotated[MLDSAParameterSet, typer.Argument(help="FIPS 204 parameter set.")],
    private_key_out: Annotated[
        Path,
        typer.Option("--private-key-out", help="Write unencrypted PKCS#8 PEM here."),
    ],
    public_key_out: Annotated[
        Path,
        typer.Option("--public-key-out", help="Write SubjectPublicKeyInfo PEM here."),
    ],
    overwrite: Annotated[bool, typer.Option("--overwrite", help="Replace existing files.")] = False,
) -> None:
    """Generate an ML-DSA key pair through OpenSSL 3.5+ EVP."""

    def factory() -> PQCKeyGenerationView:
        result = generate_ml_dsa_key_pair(parameter_set)
        _write_key_pair(
            private_key_out,
            public_key_out,
            private_pem=result.private_pem,
            public_pem=result.public_pem,
            overwrite=overwrite,
        )
        return PQCKeyGenerationView(result, str(private_key_out), str(public_key_out))

    _run(context, factory)


def _read_message(
    *,
    message_text: str | None,
    message_hex: str | None,
    message_file: Path | None,
) -> ByteInput:
    return read_byte_source(
        label="message",
        text=message_text,
        hex_value=message_hex,
        file=message_file,
    )


@ml_dsa_app.command("sign")
def ml_dsa_sign_command(
    context: typer.Context,
    parameter_set: Annotated[MLDSAParameterSet, typer.Argument(help="FIPS 204 parameter set.")],
    private_key_file: Annotated[
        Path,
        typer.Option("--private-key-file", help="Unencrypted ML-DSA PKCS#8 PEM key."),
    ],
    message_text: Annotated[str | None, typer.Option("--message-text")] = None,
    message_hex: Annotated[str | None, typer.Option("--message-hex")] = None,
    message_file: Annotated[Path | None, typer.Option("--message-file")] = None,
    context_text: Annotated[str | None, typer.Option("--context-text")] = None,
    context_hex: Annotated[str | None, typer.Option("--context-hex")] = None,
    signature_out: Annotated[Path | None, typer.Option("--signature-out")] = None,
    overwrite: Annotated[bool, typer.Option("--overwrite")] = False,
) -> None:
    """Sign a raw message with pure ML-DSA and optional context."""

    def factory() -> PQCSignatureView:
        message = _read_message(
            message_text=message_text,
            message_hex=message_hex,
            message_file=message_file,
        )
        result = ml_dsa_sign(
            parameter_set,
            _read_file(private_key_file, label="ML-DSA private key"),
            message.data,
            context=_context_bytes(context_text, context_hex),
        )
        if signature_out is not None:
            _write_atomic_bytes(
                signature_out,
                bytes.fromhex(result.signature_hex),
                mode=0o644,
                overwrite=overwrite,
            )
        return PQCSignatureView(
            result,
            message.source_kind,
            None if signature_out is None else str(signature_out),
        )

    _run(context, factory)


@ml_dsa_app.command("verify")
def ml_dsa_verify_command(
    context: typer.Context,
    parameter_set: Annotated[MLDSAParameterSet, typer.Argument(help="FIPS 204 parameter set.")],
    public_key_file: Annotated[
        Path,
        typer.Option("--public-key-file", help="ML-DSA SubjectPublicKeyInfo PEM key."),
    ],
    signature_hex: Annotated[str | None, typer.Option("--signature-hex")] = None,
    signature_file: Annotated[Path | None, typer.Option("--signature-file")] = None,
    message_text: Annotated[str | None, typer.Option("--message-text")] = None,
    message_hex: Annotated[str | None, typer.Option("--message-hex")] = None,
    message_file: Annotated[Path | None, typer.Option("--message-file")] = None,
    context_text: Annotated[str | None, typer.Option("--context-text")] = None,
    context_hex: Annotated[str | None, typer.Option("--context-hex")] = None,
) -> None:
    """Verify a pure ML-DSA signature and matching context."""

    def factory() -> PQCVerificationView:
        signature = _read_hex_or_file(
            label="signature", hex_value=signature_hex, file=signature_file
        )
        message = _read_message(
            message_text=message_text,
            message_hex=message_hex,
            message_file=message_file,
        )
        result = ml_dsa_verify(
            parameter_set,
            _read_file(public_key_file, label="ML-DSA public key"),
            message.data,
            signature.data,
            context=_context_bytes(context_text, context_hex),
        )
        if not result.valid:
            raise VerificationError("ML-DSA signature verification failed.")
        return PQCVerificationView(result)

    _run(context, factory)


@slh_dsa_app.command("parameters")
def slh_dsa_parameters_command(context: typer.Context) -> None:
    """List all twelve FIPS 205 parameter sets and raw standardized sizes."""

    _run(context, lambda: SLHDSAParametersView(slh_dsa_parameter_profiles()))


@slh_dsa_app.command("generate")
def slh_dsa_generate_command(
    context: typer.Context,
    parameter_set: Annotated[SLHDSAParameterSet, typer.Argument(help="FIPS 205 parameter set.")],
    private_key_out: Annotated[
        Path,
        typer.Option("--private-key-out", help="Write unencrypted PKCS#8 PEM here."),
    ],
    public_key_out: Annotated[
        Path,
        typer.Option("--public-key-out", help="Write SubjectPublicKeyInfo PEM here."),
    ],
    overwrite: Annotated[bool, typer.Option("--overwrite", help="Replace existing files.")] = False,
) -> None:
    """Generate an SLH-DSA key pair through OpenSSL 3.5+ EVP."""

    def factory() -> PQCKeyGenerationView:
        result = generate_slh_dsa_key_pair(parameter_set)
        _write_key_pair(
            private_key_out,
            public_key_out,
            private_pem=result.private_pem,
            public_pem=result.public_pem,
            overwrite=overwrite,
        )
        return PQCKeyGenerationView(result, str(private_key_out), str(public_key_out))

    _run(context, factory)


@slh_dsa_app.command("sign")
def slh_dsa_sign_command(
    context: typer.Context,
    parameter_set: Annotated[SLHDSAParameterSet, typer.Argument(help="FIPS 205 parameter set.")],
    private_key_file: Annotated[
        Path,
        typer.Option("--private-key-file", help="Unencrypted SLH-DSA PKCS#8 PEM key."),
    ],
    message_text: Annotated[str | None, typer.Option("--message-text")] = None,
    message_hex: Annotated[str | None, typer.Option("--message-hex")] = None,
    message_file: Annotated[Path | None, typer.Option("--message-file")] = None,
    context_text: Annotated[str | None, typer.Option("--context-text")] = None,
    context_hex: Annotated[str | None, typer.Option("--context-hex")] = None,
    signature_out: Annotated[Path | None, typer.Option("--signature-out")] = None,
    overwrite: Annotated[bool, typer.Option("--overwrite")] = False,
) -> None:
    """Sign a raw message with pure SLH-DSA and optional context."""

    def factory() -> PQCSignatureView:
        message = _read_message(
            message_text=message_text,
            message_hex=message_hex,
            message_file=message_file,
        )
        result = slh_dsa_sign(
            parameter_set,
            _read_file(private_key_file, label="SLH-DSA private key"),
            message.data,
            context=_context_bytes(context_text, context_hex),
        )
        if signature_out is not None:
            _write_atomic_bytes(
                signature_out,
                bytes.fromhex(result.signature_hex),
                mode=0o644,
                overwrite=overwrite,
            )
        return PQCSignatureView(
            result,
            message.source_kind,
            None if signature_out is None else str(signature_out),
        )

    _run(context, factory)


@slh_dsa_app.command("verify")
def slh_dsa_verify_command(
    context: typer.Context,
    parameter_set: Annotated[SLHDSAParameterSet, typer.Argument(help="FIPS 205 parameter set.")],
    public_key_file: Annotated[
        Path,
        typer.Option("--public-key-file", help="SLH-DSA SubjectPublicKeyInfo PEM key."),
    ],
    signature_hex: Annotated[str | None, typer.Option("--signature-hex")] = None,
    signature_file: Annotated[Path | None, typer.Option("--signature-file")] = None,
    message_text: Annotated[str | None, typer.Option("--message-text")] = None,
    message_hex: Annotated[str | None, typer.Option("--message-hex")] = None,
    message_file: Annotated[Path | None, typer.Option("--message-file")] = None,
    context_text: Annotated[str | None, typer.Option("--context-text")] = None,
    context_hex: Annotated[str | None, typer.Option("--context-hex")] = None,
) -> None:
    """Verify a pure SLH-DSA signature and matching context."""

    def factory() -> PQCVerificationView:
        signature = _read_hex_or_file(
            label="signature", hex_value=signature_hex, file=signature_file
        )
        message = _read_message(
            message_text=message_text,
            message_hex=message_hex,
            message_file=message_file,
        )
        result = slh_dsa_verify(
            parameter_set,
            _read_file(public_key_file, label="SLH-DSA public key"),
            message.data,
            signature.data,
            context=_context_bytes(context_text, context_hex),
        )
        if not result.valid:
            raise VerificationError("SLH-DSA signature verification failed.")
        return PQCVerificationView(result)

    _run(context, factory)


@app.command("compare-key-establishment")
def compare_key_establishment_command(context: typer.Context) -> None:
    """Compare finite-field DH, X25519, and ML-KEM."""

    _run(
        context,
        lambda: PQCComparisonView(
            "post-quantum.compare-key-establishment",
            post_quantum_key_establishment_profiles(),
        ),
    )


@app.command("compare-signatures")
def compare_signatures_command(context: typer.Context) -> None:
    """Compare RSA-PSS, Ed25519, ML-DSA, and SLH-DSA."""

    _run(
        context,
        lambda: PQCComparisonView(
            "post-quantum.compare-signatures",
            post_quantum_signature_profiles(),
        ),
    )


@app.command("overview")
def overview_command(context: typer.Context) -> None:
    """Summarize the classical/post-quantum public-key boundary in CryptoLab 1.1.0."""

    _run(
        context,
        lambda: PQCComparisonView(
            "post-quantum.overview",
            classical_post_quantum_profiles(),
        ),
    )


app.add_typer(foundations_app, name="foundations")
app.add_typer(ml_kem_app, name="ml-kem")
app.add_typer(ml_dsa_app, name="ml-dsa")
app.add_typer(slh_dsa_app, name="slh-dsa")
