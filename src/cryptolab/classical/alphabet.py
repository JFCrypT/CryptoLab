"""Ordered Unicode alphabets for educational classical ciphers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from importlib.resources import files
from json import JSONDecodeError, loads
from typing import TYPE_CHECKING, Any

from cryptolab.exceptions import InputValidationError, ResourceLimitError
from cryptolab.limits import MAX_ALPHABET_SYMBOLS, MIN_ALPHABET_SYMBOLS

if TYPE_CHECKING:
    from pathlib import Path

BUILTIN_ALPHABET_FILES = {
    "latin-upper": "latin_upper.json",
    "spanish-upper": "spanish_upper.json",
}


@dataclass(frozen=True, slots=True)
class Alphabet:
    """A finite ordered sequence of unique one-code-point symbols."""

    name: str
    symbols: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise InputValidationError("An alphabet name must not be empty.")
        if len(self.symbols) < MIN_ALPHABET_SYMBOLS:
            raise InputValidationError(
                f"An alphabet must contain at least {MIN_ALPHABET_SYMBOLS} symbols."
            )
        if len(self.symbols) > MAX_ALPHABET_SYMBOLS:
            raise ResourceLimitError(
                f"An alphabet may contain at most {MAX_ALPHABET_SYMBOLS} symbols."
            )
        if any(len(symbol) != 1 for symbol in self.symbols):
            raise InputValidationError(
                "Every alphabet symbol must be exactly one Unicode code point."
            )
        if len(set(self.symbols)) != len(self.symbols):
            raise InputValidationError("Alphabet symbols must be unique.")

    def index_map(self) -> dict[str, int]:
        """Return the symbol-to-index map for this alphabet."""

        return {symbol: index for index, symbol in enumerate(self.symbols)}


class UnknownSymbolPolicy(StrEnum):
    """Behavior for input symbols not present in the selected alphabet."""

    PRESERVE = "preserve"
    REJECT = "reject"


def builtin_alphabet_names() -> tuple[str, ...]:
    """Return stable names of packaged alphabets."""

    return tuple(BUILTIN_ALPHABET_FILES)


def _alphabet_from_payload(payload: Any, *, source: str) -> Alphabet:
    if not isinstance(payload, dict):
        raise InputValidationError(f"Alphabet data from {source} must be a JSON object.")
    name = payload.get("name")
    symbols = payload.get("symbols")
    if not isinstance(name, str) or not isinstance(symbols, list):
        raise InputValidationError(
            f"Alphabet data from {source} must contain string 'name' and list 'symbols'."
        )
    if not all(isinstance(symbol, str) for symbol in symbols):
        raise InputValidationError(f"Alphabet symbols from {source} must be strings.")
    return Alphabet(name=name, symbols=tuple(symbols))


def load_builtin_alphabet(name: str) -> Alphabet:
    """Load one packaged alphabet by its stable English name."""

    filename = BUILTIN_ALPHABET_FILES.get(name)
    if filename is None:
        choices = ", ".join(builtin_alphabet_names())
        raise InputValidationError(f"Unknown built-in alphabet '{name}'. Choose one of: {choices}.")
    resource = files("cryptolab.data.alphabets").joinpath(filename)
    payload = loads(resource.read_text(encoding="utf-8"))
    return _alphabet_from_payload(payload, source=name)


def load_alphabet_file(path: Path) -> Alphabet:
    """Load an explicit UTF-8 JSON alphabet file."""

    try:
        text = path.read_text(encoding="utf-8")
        payload = loads(text)
    except OSError as error:
        raise InputValidationError(f"Unable to read alphabet file: {path}") from error
    except JSONDecodeError as error:
        raise InputValidationError(f"Alphabet file is not valid JSON: {path}") from error
    return _alphabet_from_payload(payload, source=str(path))
