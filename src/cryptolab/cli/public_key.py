"""CLI commands for educational and library-backed public-key cryptography."""

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
from cryptolab.public_key.diffie_hellman import (
    DEFAULT_DH_DERIVED_KEY_BYTES,
    DEFAULT_DH_HKDF_INFO_TEXT,
    inspect_dh_group,
    perform_dh_exchange,
)
from cryptolab.public_key.rsa_applied import (
    generate_rsa_key_pair,
    load_rsa_private_key,
    load_rsa_public_key,
    rsa_oaep_decrypt,
    rsa_oaep_encrypt,
    rsa_profiles,
    rsa_pss_sign,
    rsa_pss_verify,
)
from cryptolab.public_key.rsa_educational import (
    DEFAULT_EDUCATIONAL_RSA_PUBLIC_EXPONENT,
    build_educational_rsa_key,
    bytes_to_integer,
    generate_educational_rsa_key,
    integer_to_bytes,
    textbook_rsa_decrypt,
    textbook_rsa_encrypt,
)
from cryptolab.rendering.diffie_hellman import DHExchangeView, DHGroupView
from cryptolab.rendering.rsa import (
    EducationalRSADecryptionView,
    EducationalRSAGenerationView,
    EducationalRSAKeyView,
    EducationalRSAOperationView,
    IntegerBytesView,
    RSAComparisonView,
    RSAKeyGenerationView,
    RSAOAEPView,
    RSAPSSVerificationView,
    RSAPSSView,
)

if TYPE_CHECKING:
    from cryptolab.rendering.common import SupportsRender


app = typer.Typer(
    name="public-key",
    help="Study educational and library-backed public-key cryptography.",
    no_args_is_help=True,
)
rsa_app = typer.Typer(
    name="rsa",
    help="Inspect textbook RSA and use RSA-OAEP and RSA-PSS through cryptography.",
    no_args_is_help=True,
)
educational_app = typer.Typer(
    name="educational",
    help="Inspect transparent textbook RSA over deliberately small primes.",
    no_args_is_help=True,
)
applied_app = typer.Typer(
    name="applied",
    help="Use RSA-OAEP, RSA-PSS, and PEM serialization through cryptography.",
    no_args_is_help=True,
)
convert_app = typer.Typer(
    name="convert",
    help="Convert unsigned integers and bytes using CryptoLab's big-endian convention.",
    no_args_is_help=True,
)
dh_app = typer.Typer(
    name="dh",
    help="Inspect educational finite-field Diffie-Hellman over small prime fields.",
    no_args_is_help=True,
)


def _run(context: typer.Context, factory: Callable[[], SupportsRender]) -> None:
    try:
        execute(context, factory())
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


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


def _validate_output_paths(private_path: Path, public_path: Path, *, overwrite: bool) -> None:
    if private_path.absolute() == public_path.absolute():
        raise OutputError("Private-key and public-key output paths must differ.")
    for path in (private_path, public_path):
        if path.exists() and not overwrite:
            raise OutputError(f"Output file already exists: {path}; use --overwrite to replace it.")


def _write_atomic_bytes(path: Path, data: bytes, *, mode: int) -> None:
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


@educational_app.command("inspect")
def educational_inspect_command(
    context: typer.Context,
    p: Annotated[int, typer.Argument(help="First small prime.")],
    q: Annotated[int, typer.Argument(help="Second distinct small prime.")],
    e: Annotated[int, typer.Argument(help="Public exponent.")],
) -> None:
    """Compute n, phi(n), lambda(n), d, and CRT parameters."""

    _run(context, lambda: EducationalRSAKeyView(build_educational_rsa_key(p, q, e)))


@educational_app.command("generate")
def educational_generate_command(
    context: typer.Context,
    prime_bits: Annotated[
        int,
        typer.Option("--prime-bits", help="Bit length of each deliberately small prime."),
    ] = 12,
    e: Annotated[
        int,
        typer.Option("--e", help="Public exponent; 65537 is the educational default."),
    ] = DEFAULT_EDUCATIONAL_RSA_PUBLIC_EXPONENT,
) -> None:
    """Generate a bounded educational RSA key using the system randomness source."""

    _run(
        context,
        lambda: EducationalRSAGenerationView(
            generate_educational_rsa_key(prime_bits=prime_bits, e=e)
        ),
    )


@educational_app.command("encrypt")
def educational_encrypt_command(
    context: typer.Context,
    message: Annotated[int, typer.Argument(help="Integer representative 0 <= m < n.")],
    p: Annotated[int, typer.Option("--p", help="First small prime.")],
    q: Annotated[int, typer.Option("--q", help="Second distinct small prime.")],
    e: Annotated[int, typer.Option("--e", help="Public exponent.")],
) -> None:
    """Encrypt one integer representative with deterministic textbook RSA."""

    def factory() -> EducationalRSAOperationView:
        key = build_educational_rsa_key(p, q, e)
        return EducationalRSAOperationView(textbook_rsa_encrypt(message, key))

    _run(context, factory)


@educational_app.command("decrypt")
def educational_decrypt_command(
    context: typer.Context,
    ciphertext: Annotated[int, typer.Argument(help="Integer representative 0 <= c < n.")],
    p: Annotated[int, typer.Option("--p", help="First small prime.")],
    q: Annotated[int, typer.Option("--q", help="Second distinct small prime.")],
    e: Annotated[int, typer.Option("--e", help="Public exponent.")],
) -> None:
    """Decrypt textbook RSA and expose the CRT reconstruction."""

    def factory() -> EducationalRSADecryptionView:
        key = build_educational_rsa_key(p, q, e)
        return EducationalRSADecryptionView(textbook_rsa_decrypt(ciphertext, key))

    _run(context, factory)


@convert_app.command("integer-to-bytes", context_settings={"ignore_unknown_options": True})
def integer_to_bytes_command(
    context: typer.Context,
    value: Annotated[int, typer.Argument(help="Non-negative integer.")],
    length: Annotated[
        int | None,
        typer.Option("--length", help="Optional explicit output length in bytes."),
    ] = None,
) -> None:
    """Encode an unsigned integer as big-endian bytes."""

    _run(context, lambda: IntegerBytesView(integer_to_bytes(value, length=length)))


@convert_app.command("bytes-to-integer")
def bytes_to_integer_command(
    context: typer.Context,
    value: Annotated[str, typer.Argument(help="Canonical hexadecimal bytes.")],
) -> None:
    """Decode non-empty big-endian bytes as an unsigned integer."""

    _run(
        context,
        lambda: IntegerBytesView(
            bytes_to_integer(parse_hex_bytes(value, label="integer byte representation"))
        ),
    )


@applied_app.command("generate")
def applied_generate_command(
    context: typer.Context,
    private_key_out: Annotated[
        Path,
        typer.Option("--private-key-out", help="Write unencrypted PKCS#8 PEM here."),
    ],
    public_key_out: Annotated[
        Path,
        typer.Option("--public-key-out", help="Write SubjectPublicKeyInfo PEM here."),
    ],
    key_size: Annotated[
        int,
        typer.Option("--key-size", help="RSA modulus size: 2048, 3072, or 4096 bits."),
    ] = 2048,
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Replace existing output files explicitly."),
    ] = False,
) -> None:
    """Generate an RSA key pair and serialize it to local PEM files."""

    def factory() -> RSAKeyGenerationView:
        _validate_output_paths(private_key_out, public_key_out, overwrite=overwrite)
        result = generate_rsa_key_pair(key_size=key_size)
        _write_atomic_bytes(private_key_out, result.private_pem, mode=0o600)
        _write_atomic_bytes(public_key_out, result.public_pem, mode=0o644)
        return RSAKeyGenerationView(result, str(private_key_out), str(public_key_out))

    _run(context, factory)


@applied_app.command("oaep-encrypt")
def oaep_encrypt_command(
    context: typer.Context,
    public_key_file: Annotated[
        Path,
        typer.Option("--public-key-file", help="PEM-encoded RSA public key."),
    ],
    plaintext_text: Annotated[
        str | None,
        typer.Option("--plaintext-text", help="Plaintext encoded strictly as UTF-8."),
    ] = None,
    plaintext_hex: Annotated[
        str | None,
        typer.Option("--plaintext-hex", help="Plaintext canonical hexadecimal bytes."),
    ] = None,
    plaintext_file: Annotated[
        Path | None,
        typer.Option("--plaintext-file", help="Read plaintext bytes from a file."),
    ] = None,
) -> None:
    """Encrypt a short message with RSA-OAEP using SHA-256."""

    def factory() -> RSAOAEPView:
        public_key = load_rsa_public_key(_read_file(public_key_file, label="public key"))
        plaintext = read_byte_source(
            label="plaintext",
            text=plaintext_text,
            hex_value=plaintext_hex,
            file=plaintext_file,
        )
        return RSAOAEPView(rsa_oaep_encrypt(public_key, plaintext.data), plaintext.source_kind)

    _run(context, factory)


@applied_app.command("oaep-decrypt")
def oaep_decrypt_command(
    context: typer.Context,
    private_key_file: Annotated[
        Path,
        typer.Option("--private-key-file", help="Unencrypted PEM-encoded RSA private key."),
    ],
    ciphertext_hex: Annotated[
        str | None,
        typer.Option("--ciphertext-hex", help="Ciphertext canonical hexadecimal bytes."),
    ] = None,
    ciphertext_file: Annotated[
        Path | None,
        typer.Option("--ciphertext-file", help="Read ciphertext bytes from a file."),
    ] = None,
) -> None:
    """Decrypt RSA-OAEP ciphertext using SHA-256."""

    def factory() -> RSAOAEPView:
        private_key = load_rsa_private_key(_read_file(private_key_file, label="private key"))
        ciphertext = _read_hex_or_file(
            label="ciphertext",
            hex_value=ciphertext_hex,
            file=ciphertext_file,
        )
        return RSAOAEPView(
            rsa_oaep_decrypt(private_key, ciphertext.data),
            ciphertext.source_kind,
        )

    _run(context, factory)


@applied_app.command("pss-sign")
def pss_sign_command(
    context: typer.Context,
    private_key_file: Annotated[
        Path,
        typer.Option("--private-key-file", help="Unencrypted PEM-encoded RSA private key."),
    ],
    message_text: Annotated[
        str | None,
        typer.Option("--message-text", help="Message encoded strictly as UTF-8."),
    ] = None,
    message_hex: Annotated[
        str | None,
        typer.Option("--message-hex", help="Message canonical hexadecimal bytes."),
    ] = None,
    message_file: Annotated[
        Path | None,
        typer.Option("--message-file", help="Read message bytes from a file."),
    ] = None,
) -> None:
    """Create an RSA-PSS signature using SHA-256."""

    def factory() -> RSAPSSView:
        private_key = load_rsa_private_key(_read_file(private_key_file, label="private key"))
        message = read_byte_source(
            label="message",
            text=message_text,
            hex_value=message_hex,
            file=message_file,
        )
        return RSAPSSView(rsa_pss_sign(private_key, message.data), message.source_kind)

    _run(context, factory)


@applied_app.command("pss-verify")
def pss_verify_command(
    context: typer.Context,
    public_key_file: Annotated[
        Path,
        typer.Option("--public-key-file", help="PEM-encoded RSA public key."),
    ],
    signature_hex: Annotated[
        str | None,
        typer.Option("--signature-hex", help="Signature canonical hexadecimal bytes."),
    ] = None,
    signature_file: Annotated[
        Path | None,
        typer.Option("--signature-file", help="Read signature bytes from a file."),
    ] = None,
    message_text: Annotated[
        str | None,
        typer.Option("--message-text", help="Message encoded strictly as UTF-8."),
    ] = None,
    message_hex: Annotated[
        str | None,
        typer.Option("--message-hex", help="Message canonical hexadecimal bytes."),
    ] = None,
    message_file: Annotated[
        Path | None,
        typer.Option("--message-file", help="Read message bytes from a file."),
    ] = None,
) -> None:
    """Verify an RSA-PSS signature using SHA-256."""

    def factory() -> RSAPSSVerificationView:
        public_key = load_rsa_public_key(_read_file(public_key_file, label="public key"))
        signature = _read_hex_or_file(
            label="signature",
            hex_value=signature_hex,
            file=signature_file,
        )
        message = read_byte_source(
            label="message",
            text=message_text,
            hex_value=message_hex,
            file=message_file,
        )
        result = rsa_pss_verify(public_key, message.data, signature.data)
        if not result.valid:
            raise VerificationError("RSA-PSS signature verification failed.")
        return RSAPSSVerificationView(result)

    _run(context, factory)


@dh_app.command("group")
def dh_group_command(
    context: typer.Context,
    prime: Annotated[int, typer.Argument(help="Small prime modulus p.")],
    generator: Annotated[int, typer.Argument(help="Candidate generator g in Z_p^*.")],
) -> None:
    """Inspect the multiplicative group and validate a generator candidate."""

    _run(context, lambda: DHGroupView(inspect_dh_group(prime, generator)))


@dh_app.command("exchange")
def dh_exchange_command(
    context: typer.Context,
    prime: Annotated[int, typer.Argument(help="Small prime modulus p.")],
    generator: Annotated[int, typer.Argument(help="Generator g of Z_p^*.")],
    alice_private: Annotated[int, typer.Argument(help="Alice private exponent a.")],
    bob_private: Annotated[int, typer.Argument(help="Bob private exponent b.")],
    salt_hex: Annotated[
        str | None,
        typer.Option("--salt-hex", help="Optional HKDF salt as canonical hexadecimal bytes."),
    ] = None,
    info_text: Annotated[
        str,
        typer.Option("--info-text", help="HKDF context encoded strictly as UTF-8."),
    ] = DEFAULT_DH_HKDF_INFO_TEXT,
    length: Annotated[
        int,
        typer.Option("--length", help="Derived session-key length in bytes."),
    ] = DEFAULT_DH_DERIVED_KEY_BYTES,
) -> None:
    """Compute public values, a shared secret, and an HKDF-SHA-256 session key."""

    salt = None if salt_hex is None else parse_hex_bytes(salt_hex, label="HKDF salt")
    _run(
        context,
        lambda: DHExchangeView(
            perform_dh_exchange(
                prime=prime,
                generator=generator,
                alice_private=alice_private,
                bob_private=bob_private,
                salt=salt,
                info=info_text.encode("utf-8", errors="strict"),
                derived_key_length=length,
            )
        ),
    )


@rsa_app.command("compare")
def rsa_compare_command(context: typer.Context) -> None:
    """Compare textbook RSA, RSA-OAEP, and RSA-PSS by purpose and limitations."""

    _run(context, lambda: RSAComparisonView(rsa_profiles()))


rsa_app.add_typer(educational_app, name="educational")
rsa_app.add_typer(convert_app, name="convert")
rsa_app.add_typer(applied_app, name="applied")
app.add_typer(rsa_app, name="rsa")
app.add_typer(dh_app, name="dh")

__all__ = ["app"]
