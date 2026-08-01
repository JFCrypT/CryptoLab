"""CLI commands for the approved controlled cryptanalysis laboratories."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from cryptolab.classical.alphabet import (
    Alphabet,
    UnknownSymbolPolicy,
    load_alphabet_file,
    load_builtin_alphabet,
)
from cryptolab.cli.common import execute
from cryptolab.encoding import parse_hex_bytes
from cryptolab.exceptions import CryptoLabError, InputValidationError
from cryptolab.labs.caesar_brute_force import run_caesar_brute_force_lab
from cryptolab.labs.models import APPROVED_LABS
from cryptolab.labs.vernam_key_reuse import run_vernam_key_reuse_lab
from cryptolab.rendering.labs import (
    CaesarBruteForceLabView,
    LabListView,
    VernamKeyReuseLabView,
)

if TYPE_CHECKING:
    from cryptolab.rendering.common import SupportsRender

DEFAULT_ALPHABET = "latin-upper"

app = typer.Typer(
    name="lab",
    help="Run only the explicitly approved controlled cryptanalysis laboratories.",
    no_args_is_help=True,
)


def _run(context: typer.Context, factory: Callable[[], SupportsRender]) -> None:
    try:
        execute(context, factory())
    except CryptoLabError as error:
        Console(stderr=True, no_color=True).print(f"Error: {error}")
        raise typer.Exit(code=error.exit_code) from error


def _resolve_alphabet(name: str | None, path: Path | None) -> Alphabet:
    if name is not None and path is not None:
        raise InputValidationError("Use either --alphabet or --alphabet-file, not both.")
    if path is not None:
        return load_alphabet_file(path)
    return load_builtin_alphabet(name or DEFAULT_ALPHABET)


@app.command("list")
def list_labs_command(context: typer.Context) -> None:
    """List the exact four laboratories approved for version 1.0.0."""

    _run(context, lambda: LabListView(APPROVED_LABS))


@app.command("caesar-brute-force")
def caesar_brute_force_command(
    context: typer.Context,
    ciphertext: Annotated[str, typer.Argument(help="Local Caesar ciphertext.")],
    alphabet: Annotated[
        str | None, typer.Option("--alphabet", help="Built-in alphabet name.")
    ] = None,
    alphabet_file: Annotated[
        Path | None,
        typer.Option("--alphabet-file", help="Explicit UTF-8 JSON alphabet file."),
    ] = None,
    unknown: Annotated[
        UnknownSymbolPolicy,
        typer.Option(
            "--unknown-symbols",
            "--unknown",
            help="Preserve or reject symbols outside the alphabet.",
        ),
    ] = UnknownSymbolPolicy.PRESERVE,
) -> None:
    """Enumerate the complete small Caesar key space."""

    _run(
        context,
        lambda: CaesarBruteForceLabView(
            run_caesar_brute_force_lab(
                ciphertext,
                _resolve_alphabet(alphabet, alphabet_file),
                unknown,
            )
        ),
    )


@app.command("vernam-key-reuse")
def vernam_key_reuse_command(
    context: typer.Context,
    message_one_hex: Annotated[
        str, typer.Option("--message-one-hex", help="First local plaintext in hexadecimal.")
    ],
    message_two_hex: Annotated[
        str, typer.Option("--message-two-hex", help="Second local plaintext in hexadecimal.")
    ],
    key_hex: Annotated[
        str, typer.Option("--key-hex", help="Deliberately reused equal-length key.")
    ],
) -> None:
    """Demonstrate the consequence of reusing a Vernam keystream."""

    _run(
        context,
        lambda: VernamKeyReuseLabView(
            run_vernam_key_reuse_lab(
                parse_hex_bytes(message_one_hex, label="first message"),
                parse_hex_bytes(message_two_hex, label="second message"),
                parse_hex_bytes(key_hex, label="reused key"),
            )
        ),
    )
