"""CLI commands for library-backed modern symmetric cryptography."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from cryptolab.cli.common import execute
from cryptolab.encoding import ByteInput, parse_hex_bytes, read_byte_source
from cryptolab.exceptions import CryptoLabError, InputValidationError
from cryptolab.rendering.modern_symmetric import (
    AEADComparisonView,
    AESModeComparisonView,
    ModernCipherView,
)
from cryptolab.symmetric.modern import (
    AESMode,
    PaddingMode,
    aead_profiles,
    aes_decrypt,
    aes_encrypt,
    aes_mode_profiles,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)

if TYPE_CHECKING:
    from cryptolab.rendering.common import SupportsRender


aes_app = typer.Typer(
    name="aes",
    help="Use AES-128 or AES-256 through the cryptography library.",
    no_args_is_help=True,
)
chacha_app = typer.Typer(
    name="chacha20-poly1305",
    help="Use ChaCha20-Poly1305 through the cryptography library.",
    no_args_is_help=True,
)


def _run(context: typer.Context, factory: Callable[[], SupportsRender]) -> None:
    try:
        execute(context, factory())
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


def _optional_hex(value: str | None, *, label: str) -> bytes | None:
    if value is None:
        return None
    return parse_hex_bytes(value, label=label)


def _optional_aad(
    *,
    text: str | None,
    hex_value: str | None,
    file: Path | None,
) -> ByteInput:
    if text is None and hex_value is None and file is None:
        return ByteInput(label="aad", source_kind="empty", data=b"")
    return read_byte_source(label="aad", text=text, hex_value=hex_value, file=file)


def _ciphertext_input(
    *,
    hex_value: str | None,
    file: Path | None,
) -> ByteInput:
    if (hex_value is None) == (file is None):
        raise InputValidationError(
            "Select exactly one source for ciphertext: --ciphertext-hex or --ciphertext-file."
        )
    return read_byte_source(
        label="ciphertext",
        text=None,
        hex_value=hex_value,
        file=file,
    )


def _source_description(primary: ByteInput, aad: ByteInput) -> str:
    if aad.source_kind == "empty":
        return primary.source_kind
    return f"{primary.source_kind}; aad={aad.source_kind}"


@aes_app.command("encrypt")
def aes_encrypt_command(
    context: typer.Context,
    mode: Annotated[AESMode, typer.Argument(help="AES mode.")],
    key_hex: Annotated[
        str,
        typer.Option(
            "--key-hex",
            help="16/32-byte AES key, or 32/64-byte XTS key.",
        ),
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
    padding: Annotated[
        PaddingMode,
        typer.Option(
            "--padding",
            help="PKCS#7 or none; PKCS#7 is valid only for ECB/CBC.",
        ),
    ] = PaddingMode.NONE,
    iv_hex: Annotated[
        str | None,
        typer.Option("--iv-hex", help="16-byte IV for CBC, CFB-128, or OFB."),
    ] = None,
    counter_hex: Annotated[
        str | None,
        typer.Option("--counter-hex", help="16-byte initial counter block for CTR."),
    ] = None,
    nonce_hex: Annotated[
        str | None,
        typer.Option("--nonce-hex", help="12-byte nonce for GCM."),
    ] = None,
    tweak_hex: Annotated[
        str | None,
        typer.Option("--tweak-hex", help="16-byte XTS tweak."),
    ] = None,
    aad_text: Annotated[
        str | None,
        typer.Option("--aad-text", help="AAD encoded as UTF-8."),
    ] = None,
    aad_hex: Annotated[
        str | None,
        typer.Option("--aad-hex", help="AAD hexadecimal bytes."),
    ] = None,
    aad_file: Annotated[
        Path | None,
        typer.Option("--aad-file", help="Read AAD from a file."),
    ] = None,
) -> None:
    """Encrypt bytes using one approved AES mode."""

    def factory() -> ModernCipherView:
        plaintext = read_byte_source(
            label="plaintext",
            text=plaintext_text,
            hex_value=plaintext_hex,
            file=plaintext_file,
        )
        aad = _optional_aad(text=aad_text, hex_value=aad_hex, file=aad_file)
        result = aes_encrypt(
            mode=mode,
            key=parse_hex_bytes(key_hex, label="AES key"),
            plaintext=plaintext.data,
            padding_mode=padding,
            iv=_optional_hex(iv_hex, label="IV"),
            counter=_optional_hex(counter_hex, label="counter block"),
            nonce=_optional_hex(nonce_hex, label="nonce"),
            tweak=_optional_hex(tweak_hex, label="tweak"),
            aad=aad.data,
        )
        return ModernCipherView(result, _source_description(plaintext, aad))

    _run(context, factory)


@aes_app.command("decrypt")
def aes_decrypt_command(
    context: typer.Context,
    mode: Annotated[AESMode, typer.Argument(help="AES mode.")],
    key_hex: Annotated[
        str,
        typer.Option(
            "--key-hex",
            help="16/32-byte AES key, or 32/64-byte XTS key.",
        ),
    ],
    ciphertext_hex: Annotated[
        str | None,
        typer.Option("--ciphertext-hex", help="Ciphertext canonical hexadecimal bytes."),
    ] = None,
    ciphertext_file: Annotated[
        Path | None,
        typer.Option("--ciphertext-file", help="Read ciphertext bytes from a file."),
    ] = None,
    padding: Annotated[
        PaddingMode,
        typer.Option("--padding", help="PKCS#7 or none; must match encryption."),
    ] = PaddingMode.NONE,
    iv_hex: Annotated[
        str | None,
        typer.Option("--iv-hex", help="16-byte IV for CBC, CFB-128, or OFB."),
    ] = None,
    counter_hex: Annotated[
        str | None,
        typer.Option("--counter-hex", help="16-byte initial counter block for CTR."),
    ] = None,
    nonce_hex: Annotated[
        str | None,
        typer.Option("--nonce-hex", help="12-byte nonce for GCM."),
    ] = None,
    tweak_hex: Annotated[
        str | None,
        typer.Option("--tweak-hex", help="16-byte XTS tweak."),
    ] = None,
    tag_hex: Annotated[
        str | None,
        typer.Option("--tag-hex", help="16-byte authentication tag for GCM."),
    ] = None,
    aad_text: Annotated[
        str | None,
        typer.Option("--aad-text", help="AAD encoded as UTF-8."),
    ] = None,
    aad_hex: Annotated[
        str | None,
        typer.Option("--aad-hex", help="AAD hexadecimal bytes."),
    ] = None,
    aad_file: Annotated[
        Path | None,
        typer.Option("--aad-file", help="Read AAD from a file."),
    ] = None,
) -> None:
    """Decrypt bytes using one approved AES mode."""

    def factory() -> ModernCipherView:
        ciphertext = _ciphertext_input(hex_value=ciphertext_hex, file=ciphertext_file)
        aad = _optional_aad(text=aad_text, hex_value=aad_hex, file=aad_file)
        result = aes_decrypt(
            mode=mode,
            key=parse_hex_bytes(key_hex, label="AES key"),
            ciphertext=ciphertext.data,
            padding_mode=padding,
            iv=_optional_hex(iv_hex, label="IV"),
            counter=_optional_hex(counter_hex, label="counter block"),
            nonce=_optional_hex(nonce_hex, label="nonce"),
            tweak=_optional_hex(tweak_hex, label="tweak"),
            aad=aad.data,
            tag=_optional_hex(tag_hex, label="authentication tag"),
        )
        return ModernCipherView(result, _source_description(ciphertext, aad))

    _run(context, factory)


@aes_app.command("compare-modes")
def aes_compare_modes_command(context: typer.Context) -> None:
    """Compare ECB, CBC, CFB-128, OFB, CTR, GCM, and XTS contextually."""

    _run(context, lambda: AESModeComparisonView(aes_mode_profiles()))


@chacha_app.command("encrypt")
def chacha_encrypt_command(
    context: typer.Context,
    key_hex: Annotated[str, typer.Option("--key-hex", help="32-byte key.")],
    nonce_hex: Annotated[str, typer.Option("--nonce-hex", help="12-byte nonce.")],
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
    aad_text: Annotated[
        str | None,
        typer.Option("--aad-text", help="AAD encoded as UTF-8."),
    ] = None,
    aad_hex: Annotated[
        str | None,
        typer.Option("--aad-hex", help="AAD hexadecimal bytes."),
    ] = None,
    aad_file: Annotated[
        Path | None,
        typer.Option("--aad-file", help="Read AAD from a file."),
    ] = None,
) -> None:
    """Encrypt and authenticate with ChaCha20-Poly1305."""

    def factory() -> ModernCipherView:
        plaintext = read_byte_source(
            label="plaintext",
            text=plaintext_text,
            hex_value=plaintext_hex,
            file=plaintext_file,
        )
        aad = _optional_aad(text=aad_text, hex_value=aad_hex, file=aad_file)
        result = chacha20_poly1305_encrypt(
            key=parse_hex_bytes(key_hex, label="ChaCha20-Poly1305 key"),
            nonce=parse_hex_bytes(nonce_hex, label="ChaCha20-Poly1305 nonce"),
            plaintext=plaintext.data,
            aad=aad.data,
        )
        return ModernCipherView(result, _source_description(plaintext, aad))

    _run(context, factory)


@chacha_app.command("decrypt")
def chacha_decrypt_command(
    context: typer.Context,
    key_hex: Annotated[str, typer.Option("--key-hex", help="32-byte key.")],
    nonce_hex: Annotated[str, typer.Option("--nonce-hex", help="12-byte nonce.")],
    tag_hex: Annotated[
        str,
        typer.Option("--tag-hex", help="16-byte authentication tag."),
    ],
    ciphertext_hex: Annotated[
        str | None,
        typer.Option("--ciphertext-hex", help="Ciphertext canonical hexadecimal bytes."),
    ] = None,
    ciphertext_file: Annotated[
        Path | None,
        typer.Option("--ciphertext-file", help="Read ciphertext bytes from a file."),
    ] = None,
    aad_text: Annotated[
        str | None,
        typer.Option("--aad-text", help="AAD encoded as UTF-8."),
    ] = None,
    aad_hex: Annotated[
        str | None,
        typer.Option("--aad-hex", help="AAD hexadecimal bytes."),
    ] = None,
    aad_file: Annotated[
        Path | None,
        typer.Option("--aad-file", help="Read AAD from a file."),
    ] = None,
) -> None:
    """Authenticate and decrypt with ChaCha20-Poly1305."""

    def factory() -> ModernCipherView:
        ciphertext = _ciphertext_input(hex_value=ciphertext_hex, file=ciphertext_file)
        aad = _optional_aad(text=aad_text, hex_value=aad_hex, file=aad_file)
        result = chacha20_poly1305_decrypt(
            key=parse_hex_bytes(key_hex, label="ChaCha20-Poly1305 key"),
            nonce=parse_hex_bytes(nonce_hex, label="ChaCha20-Poly1305 nonce"),
            ciphertext=ciphertext.data,
            tag=parse_hex_bytes(tag_hex, label="ChaCha20-Poly1305 tag"),
            aad=aad.data,
        )
        return ModernCipherView(result, _source_description(ciphertext, aad))

    _run(context, factory)


def compare_aead_command(context: typer.Context) -> None:
    """Compare AES-GCM and ChaCha20-Poly1305 contextually."""

    _run(context, lambda: AEADComparisonView(aead_profiles()))
