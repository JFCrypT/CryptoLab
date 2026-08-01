"""Educational Vigenère cipher with explicit repeated-key alignment."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.classical.alphabet import Alphabet, UnknownSymbolPolicy
from cryptolab.exceptions import InputValidationError


@dataclass(frozen=True, slots=True)
class VigenereAlignmentEntry:
    """One message/key alignment and modular transformation step."""

    position: int
    input_symbol: str
    input_index: int | None
    key_position: int | None
    key_symbol: str | None
    key_index: int | None
    output_index: int | None
    output_symbol: str
    transformed: bool


@dataclass(frozen=True, slots=True)
class VigenereResult:
    """Vigenère encryption or decryption result."""

    operation: str
    text: str
    key: str
    output: str
    alphabet_name: str
    alphabet_size: int
    unknown_policy: UnknownSymbolPolicy
    alignment: tuple[VigenereAlignmentEntry, ...]


def _validate_key(key: str, alphabet: Alphabet) -> tuple[int, ...]:
    if not key:
        raise InputValidationError("A Vigenère key must not be empty.")
    index_map = alphabet.index_map()
    invalid = next(
        ((position, symbol) for position, symbol in enumerate(key) if symbol not in index_map),
        None,
    )
    if invalid is not None:
        position, symbol = invalid
        raise InputValidationError(
            f"Key symbol {symbol!r} at position {position} is not in alphabet '{alphabet.name}'."
        )
    return tuple(index_map[symbol] for symbol in key)


def _transform(
    text: str,
    key: str,
    alphabet: Alphabet,
    unknown_policy: UnknownSymbolPolicy,
    *,
    decrypt: bool,
) -> VigenereResult:
    key_indices = _validate_key(key, alphabet)
    index_map = alphabet.index_map()
    output_symbols: list[str] = []
    alignment: list[VigenereAlignmentEntry] = []
    key_position = 0

    for position, symbol in enumerate(text):
        input_index = index_map.get(symbol)
        if input_index is None:
            if unknown_policy is UnknownSymbolPolicy.REJECT:
                raise InputValidationError(
                    f"Symbol {symbol!r} at position {position} is not in alphabet "
                    f"'{alphabet.name}'."
                )
            output_symbols.append(symbol)
            alignment.append(
                VigenereAlignmentEntry(
                    position=position,
                    input_symbol=symbol,
                    input_index=None,
                    key_position=None,
                    key_symbol=None,
                    key_index=None,
                    output_index=None,
                    output_symbol=symbol,
                    transformed=False,
                )
            )
            continue

        current_key_position = key_position % len(key)
        key_symbol = key[current_key_position]
        key_index = key_indices[current_key_position]
        direction = -1 if decrypt else 1
        output_index = (input_index + direction * key_index) % len(alphabet.symbols)
        output_symbol = alphabet.symbols[output_index]
        output_symbols.append(output_symbol)
        alignment.append(
            VigenereAlignmentEntry(
                position=position,
                input_symbol=symbol,
                input_index=input_index,
                key_position=current_key_position,
                key_symbol=key_symbol,
                key_index=key_index,
                output_index=output_index,
                output_symbol=output_symbol,
                transformed=True,
            )
        )
        key_position += 1

    return VigenereResult(
        operation="decrypt" if decrypt else "encrypt",
        text=text,
        key=key,
        output="".join(output_symbols),
        alphabet_name=alphabet.name,
        alphabet_size=len(alphabet.symbols),
        unknown_policy=unknown_policy,
        alignment=tuple(alignment),
    )


def vigenere_encrypt(
    text: str,
    key: str,
    alphabet: Alphabet,
    unknown_policy: UnknownSymbolPolicy = UnknownSymbolPolicy.PRESERVE,
) -> VigenereResult:
    """Encrypt text with repeated-key Vigenère alignment."""

    return _transform(text, key, alphabet, unknown_policy, decrypt=False)


def vigenere_decrypt(
    text: str,
    key: str,
    alphabet: Alphabet,
    unknown_policy: UnknownSymbolPolicy = UnknownSymbolPolicy.PRESERVE,
) -> VigenereResult:
    """Decrypt text with repeated-key Vigenère alignment."""

    return _transform(text, key, alphabet, unknown_policy, decrypt=True)
