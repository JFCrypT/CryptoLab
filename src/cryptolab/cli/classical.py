"""Classical-cryptography CLI command hierarchy."""

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
from cryptolab.classical.caesar import (
    caesar_candidates,
    caesar_decrypt,
    caesar_encrypt,
    caesar_frequency,
    caesar_table,
)
from cryptolab.classical.polybius import (
    build_polybius_grid,
    polybius_decrypt,
    polybius_encrypt,
)
from cryptolab.classical.vigenere import vigenere_decrypt, vigenere_encrypt
from cryptolab.cli.common import execute
from cryptolab.exceptions import CryptoLabError, InputValidationError
from cryptolab.rendering.classical import (
    CaesarCandidatesView,
    CaesarTableView,
    CaesarView,
    FrequencyView,
    PolybiusGridView,
    PolybiusView,
    VigenereAlignmentView,
    VigenereView,
)

if TYPE_CHECKING:
    from cryptolab.rendering.common import SupportsRender

DEFAULT_ALPHABET = "latin-upper"

app = typer.Typer(
    name="classical",
    help="Study transparent educational classical ciphers over configurable alphabets.",
    no_args_is_help=True,
)
caesar_app = typer.Typer(name="caesar", help="Caesar cipher operations.", no_args_is_help=True)
vigenere_app = typer.Typer(
    name="vigenere",
    help="Repeated-key Vigenère cipher operations.",
    no_args_is_help=True,
)
polybius_app = typer.Typer(
    name="polybius",
    help="Polybius grid construction and coordinate operations.",
    no_args_is_help=True,
)
app.add_typer(caesar_app, name="caesar")
app.add_typer(vigenere_app, name="vigenere")
app.add_typer(polybius_app, name="polybius")


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


@caesar_app.command("encrypt", context_settings={"ignore_unknown_options": True})
def caesar_encrypt_command(
    context: typer.Context,
    text: Annotated[str, typer.Argument(help="Plaintext characters.")],
    shift: Annotated[int, typer.Argument(help="Positive, zero, or negative shift.")],
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
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
    """Encrypt text with the Caesar cipher."""

    _run(
        context,
        lambda: CaesarView(
            caesar_encrypt(text, shift, _resolve_alphabet(alphabet, alphabet_file), unknown)
        ),
    )


@caesar_app.command("decrypt", context_settings={"ignore_unknown_options": True})
def caesar_decrypt_command(
    context: typer.Context,
    text: Annotated[str, typer.Argument(help="Ciphertext characters.")],
    shift: Annotated[int, typer.Argument(help="Encryption shift to reverse.")],
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
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
    """Decrypt text with the Caesar cipher."""

    _run(
        context,
        lambda: CaesarView(
            caesar_decrypt(text, shift, _resolve_alphabet(alphabet, alphabet_file), unknown)
        ),
    )


@caesar_app.command("table", context_settings={"ignore_unknown_options": True})
def caesar_table_command(
    context: typer.Context,
    shift: Annotated[int, typer.Argument(help="Positive, zero, or negative shift.")],
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
    ] = None,
    alphabet_file: Annotated[
        Path | None,
        typer.Option("--alphabet-file", help="Explicit UTF-8 JSON alphabet file."),
    ] = None,
) -> None:
    """Display the full Caesar substitution table."""

    def factory() -> CaesarTableView:
        selected = _resolve_alphabet(alphabet, alphabet_file)
        return CaesarTableView(shift, selected.name, caesar_table(shift, selected))

    _run(context, factory)


@caesar_app.command("candidates")
def caesar_candidates_command(
    context: typer.Context,
    ciphertext: Annotated[str, typer.Argument(help="Ciphertext to decrypt under every shift.")],
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
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
    """Enumerate every Caesar plaintext candidate without automatic language ranking."""

    def factory() -> CaesarCandidatesView:
        selected = _resolve_alphabet(alphabet, alphabet_file)
        return CaesarCandidatesView(
            ciphertext,
            selected.name,
            caesar_candidates(ciphertext, selected, unknown),
        )

    _run(context, factory)


@caesar_app.command("frequency")
def caesar_frequency_command(
    context: typer.Context,
    text: Annotated[str, typer.Argument(help="Text whose alphabet symbols will be counted.")],
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
    ] = None,
    alphabet_file: Annotated[
        Path | None,
        typer.Option("--alphabet-file", help="Explicit UTF-8 JSON alphabet file."),
    ] = None,
) -> None:
    """Perform basic character-frequency counting without automatic key inference."""

    _run(
        context,
        lambda: FrequencyView(caesar_frequency(text, _resolve_alphabet(alphabet, alphabet_file))),
    )


@vigenere_app.command("encrypt")
def vigenere_encrypt_command(
    context: typer.Context,
    text: Annotated[str, typer.Argument(help="Plaintext characters.")],
    key: Annotated[str, typer.Argument(help="Non-empty key entirely inside the alphabet.")],
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
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
    """Encrypt text with repeated-key Vigenère."""

    _run(
        context,
        lambda: VigenereView(
            vigenere_encrypt(text, key, _resolve_alphabet(alphabet, alphabet_file), unknown)
        ),
    )


@vigenere_app.command("decrypt")
def vigenere_decrypt_command(
    context: typer.Context,
    text: Annotated[str, typer.Argument(help="Ciphertext characters.")],
    key: Annotated[str, typer.Argument(help="Encryption key to repeat and reverse.")],
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
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
    """Decrypt text with repeated-key Vigenère."""

    _run(
        context,
        lambda: VigenereView(
            vigenere_decrypt(text, key, _resolve_alphabet(alphabet, alphabet_file), unknown)
        ),
    )


@vigenere_app.command("align")
def vigenere_align_command(
    context: typer.Context,
    text: Annotated[str, typer.Argument(help="Message characters to align.")],
    key: Annotated[str, typer.Argument(help="Non-empty repeated key.")],
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
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
    """Display repeated-key alignment and modular indices."""

    _run(
        context,
        lambda: VigenereAlignmentView(
            vigenere_encrypt(text, key, _resolve_alphabet(alphabet, alphabet_file), unknown)
        ),
    )


@polybius_app.command("build")
def polybius_build_command(
    context: typer.Context,
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
    ] = None,
    alphabet_file: Annotated[
        Path | None,
        typer.Option("--alphabet-file", help="Explicit UTF-8 JSON alphabet file."),
    ] = None,
    rows: Annotated[int | None, typer.Option("--rows", help="Grid row count, from 2 to 9.")] = None,
    columns: Annotated[
        int | None,
        typer.Option("--columns", help="Grid column count, from 2 to 9."),
    ] = None,
) -> None:
    """Build and display a row-major Polybius grid."""

    _run(
        context,
        lambda: PolybiusGridView(
            build_polybius_grid(_resolve_alphabet(alphabet, alphabet_file), rows, columns)
        ),
    )


@polybius_app.command("encrypt")
def polybius_encrypt_command(
    context: typer.Context,
    text: Annotated[str, typer.Argument(help="Plaintext characters.")],
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
    ] = None,
    alphabet_file: Annotated[
        Path | None,
        typer.Option("--alphabet-file", help="Explicit UTF-8 JSON alphabet file."),
    ] = None,
    rows: Annotated[int | None, typer.Option("--rows", help="Grid row count, from 2 to 9.")] = None,
    columns: Annotated[
        int | None,
        typer.Option("--columns", help="Grid column count, from 2 to 9."),
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
    """Encode text as canonical Polybius coordinate tokens."""

    _run(
        context,
        lambda: PolybiusView(
            polybius_encrypt(
                text,
                _resolve_alphabet(alphabet, alphabet_file),
                unknown,
                rows=rows,
                columns=columns,
            )
        ),
    )


@polybius_app.command("decrypt")
def polybius_decrypt_command(
    context: typer.Context,
    ciphertext: Annotated[
        str,
        typer.Argument(help="Space-separated ROWCOLUMN and optional u+HEX tokens."),
    ],
    alphabet: Annotated[
        str | None,
        typer.Option("--alphabet", help="Built-in alphabet name."),
    ] = None,
    alphabet_file: Annotated[
        Path | None,
        typer.Option("--alphabet-file", help="Explicit UTF-8 JSON alphabet file."),
    ] = None,
    rows: Annotated[int | None, typer.Option("--rows", help="Grid row count, from 2 to 9.")] = None,
    columns: Annotated[
        int | None,
        typer.Option("--columns", help="Grid column count, from 2 to 9."),
    ] = None,
    unknown: Annotated[
        UnknownSymbolPolicy,
        typer.Option("--unknown-symbols", "--unknown", help="Preserve or reject u+HEX tokens."),
    ] = UnknownSymbolPolicy.PRESERVE,
) -> None:
    """Decode canonical Polybius coordinate tokens."""

    _run(
        context,
        lambda: PolybiusView(
            polybius_decrypt(
                ciphertext,
                _resolve_alphabet(alphabet, alphabet_file),
                unknown,
                rows=rows,
                columns=columns,
            )
        ),
    )
