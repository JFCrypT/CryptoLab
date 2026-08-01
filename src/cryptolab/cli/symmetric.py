"""CLI commands for educational XOR, Vernam, and One-Time Pad material."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from cryptolab.cli.common import execute
from cryptolab.encoding import read_byte_source
from cryptolab.exceptions import CryptoLabError
from cryptolab.rendering.symmetric import (
    BitXORView,
    ByteXORView,
    OTPRequirementsView,
    VernamView,
    XORTruthTableView,
)
from cryptolab.symmetric.otp import otp_requirements
from cryptolab.symmetric.vernam import vernam_decrypt, vernam_encrypt
from cryptolab.symmetric.xor import xor_bits, xor_bytes, xor_truth_table

if TYPE_CHECKING:
    from cryptolab.rendering.common import SupportsRender

app = typer.Typer(
    name="symmetric",
    help="Study transparent XOR and Vernam operations before modern symmetric cryptography.",
    no_args_is_help=True,
)
xor_app = typer.Typer(name="xor", help="Bitwise and bytewise XOR operations.", no_args_is_help=True)
vernam_app = typer.Typer(
    name="vernam", help="Equal-length Vernam encryption and decryption.", no_args_is_help=True
)
otp_app = typer.Typer(
    name="otp", help="Strict One-Time Pad requirements and limitations.", no_args_is_help=True
)
app.add_typer(xor_app, name="xor")
app.add_typer(vernam_app, name="vernam")
app.add_typer(otp_app, name="otp")


def _run(context: typer.Context, factory: Callable[[], SupportsRender]) -> None:
    try:
        execute(context, factory())
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


@xor_app.command("truth-table")
def xor_truth_table_command(context: typer.Context) -> None:
    """Display the complete XOR truth table."""

    _run(context, lambda: XORTruthTableView(xor_truth_table()))


@xor_app.command("bits")
def xor_bits_command(
    context: typer.Context,
    left: Annotated[str, typer.Argument(help="Left canonical bit string.")],
    right: Annotated[str, typer.Argument(help="Right equal-length canonical bit string.")],
) -> None:
    """XOR two equal-length bit strings."""

    _run(context, lambda: BitXORView(xor_bits(left, right)))


@xor_app.command("bytes")
def xor_bytes_command(
    context: typer.Context,
    left_text: Annotated[str | None, typer.Option("--left-text", help="Left UTF-8 text.")] = None,
    left_hex: Annotated[
        str | None, typer.Option("--left-hex", help="Left canonical hexadecimal bytes.")
    ] = None,
    left_file: Annotated[
        Path | None, typer.Option("--left-file", help="Read left bytes from a file.")
    ] = None,
    right_text: Annotated[
        str | None, typer.Option("--right-text", help="Right UTF-8 text.")
    ] = None,
    right_hex: Annotated[
        str | None, typer.Option("--right-hex", help="Right canonical hexadecimal bytes.")
    ] = None,
    right_file: Annotated[
        Path | None, typer.Option("--right-file", help="Read right bytes from a file.")
    ] = None,
) -> None:
    """XOR two explicitly sourced equal-length byte strings."""

    def factory() -> ByteXORView:
        left = read_byte_source(label="left", text=left_text, hex_value=left_hex, file=left_file)
        right = read_byte_source(
            label="right", text=right_text, hex_value=right_hex, file=right_file
        )
        return ByteXORView(xor_bytes(left.data, right.data), left.source_kind, right.source_kind)

    _run(context, factory)


@vernam_app.command("encrypt")
def vernam_encrypt_command(
    context: typer.Context,
    message_text: Annotated[
        str | None, typer.Option("--message-text", help="Plaintext encoded strictly as UTF-8.")
    ] = None,
    message_hex: Annotated[
        str | None, typer.Option("--message-hex", help="Plaintext canonical hexadecimal bytes.")
    ] = None,
    message_file: Annotated[
        Path | None, typer.Option("--message-file", help="Read plaintext bytes from a file.")
    ] = None,
    key_text: Annotated[
        str | None, typer.Option("--key-text", help="Key encoded strictly as UTF-8.")
    ] = None,
    key_hex: Annotated[
        str | None, typer.Option("--key-hex", help="Key canonical hexadecimal bytes.")
    ] = None,
    key_file: Annotated[
        Path | None, typer.Option("--key-file", help="Read key bytes from a file.")
    ] = None,
) -> None:
    """Encrypt bytes with an explicit equal-length Vernam key."""

    def factory() -> VernamView:
        message = read_byte_source(
            label="message", text=message_text, hex_value=message_hex, file=message_file
        )
        key = read_byte_source(label="key", text=key_text, hex_value=key_hex, file=key_file)
        return VernamView(
            vernam_encrypt(message.data, key.data), message.source_kind, key.source_kind
        )

    _run(context, factory)


@vernam_app.command("decrypt")
def vernam_decrypt_command(
    context: typer.Context,
    ciphertext_text: Annotated[
        str | None,
        typer.Option("--ciphertext-text", help="Ciphertext encoded strictly as UTF-8."),
    ] = None,
    ciphertext_hex: Annotated[
        str | None,
        typer.Option("--ciphertext-hex", help="Ciphertext canonical hexadecimal bytes."),
    ] = None,
    ciphertext_file: Annotated[
        Path | None, typer.Option("--ciphertext-file", help="Read ciphertext bytes from a file.")
    ] = None,
    key_text: Annotated[
        str | None, typer.Option("--key-text", help="Key encoded strictly as UTF-8.")
    ] = None,
    key_hex: Annotated[
        str | None, typer.Option("--key-hex", help="Key canonical hexadecimal bytes.")
    ] = None,
    key_file: Annotated[
        Path | None, typer.Option("--key-file", help="Read key bytes from a file.")
    ] = None,
) -> None:
    """Decrypt bytes with the same explicit equal-length Vernam key."""

    def factory() -> VernamView:
        ciphertext = read_byte_source(
            label="ciphertext",
            text=ciphertext_text,
            hex_value=ciphertext_hex,
            file=ciphertext_file,
        )
        key = read_byte_source(label="key", text=key_text, hex_value=key_hex, file=key_file)
        return VernamView(
            vernam_decrypt(ciphertext.data, key.data), ciphertext.source_kind, key.source_kind
        )

    _run(context, factory)


@otp_app.command("requirements")
def otp_requirements_command(context: typer.Context) -> None:
    """Display every condition required for a true One-Time Pad."""

    _run(context, lambda: OTPRequirementsView(otp_requirements()))
