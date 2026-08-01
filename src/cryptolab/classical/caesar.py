"""Educational Caesar cipher over configurable ordered alphabets."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.classical.alphabet import Alphabet, UnknownSymbolPolicy
from cryptolab.exceptions import InputValidationError


@dataclass(frozen=True, slots=True)
class ClassicalTransformStep:
    """One character transformation in a classical cipher."""

    position: int
    input_symbol: str
    input_index: int | None
    key_index: int | None
    output_index: int | None
    output_symbol: str
    transformed: bool


@dataclass(frozen=True, slots=True)
class CaesarResult:
    """Caesar encryption or decryption result."""

    operation: str
    text: str
    output: str
    shift: int
    normalized_shift: int
    alphabet_name: str
    alphabet_size: int
    unknown_policy: UnknownSymbolPolicy
    steps: tuple[ClassicalTransformStep, ...]


@dataclass(frozen=True, slots=True)
class CaesarTableEntry:
    """One row of a Caesar transformation table."""

    input_index: int
    input_symbol: str
    output_index: int
    output_symbol: str


@dataclass(frozen=True, slots=True)
class CaesarCandidate:
    """One plaintext candidate from exhaustive Caesar key enumeration."""

    shift: int
    plaintext: str


@dataclass(frozen=True, slots=True)
class FrequencyEntry:
    """Observed count and percentage for one alphabet symbol."""

    symbol: str
    count: int
    percentage: float


@dataclass(frozen=True, slots=True)
class FrequencyResult:
    """Basic character-frequency analysis for one alphabet."""

    text: str
    alphabet_name: str
    total_alphabet_symbols: int
    unknown_symbol_count: int
    most_frequent: tuple[str, ...]
    entries: tuple[FrequencyEntry, ...]


def _transform(
    text: str,
    shift: int,
    alphabet: Alphabet,
    unknown_policy: UnknownSymbolPolicy,
    *,
    decrypt: bool,
) -> CaesarResult:
    index_map = alphabet.index_map()
    normalized_shift = shift % len(alphabet.symbols)
    effective_shift = -normalized_shift if decrypt else normalized_shift
    output_symbols: list[str] = []
    steps: list[ClassicalTransformStep] = []

    for position, symbol in enumerate(text):
        input_index = index_map.get(symbol)
        if input_index is None:
            if unknown_policy is UnknownSymbolPolicy.REJECT:
                raise InputValidationError(
                    f"Symbol {symbol!r} at position {position} is not in alphabet "
                    f"'{alphabet.name}'."
                )
            output_symbols.append(symbol)
            steps.append(
                ClassicalTransformStep(
                    position=position,
                    input_symbol=symbol,
                    input_index=None,
                    key_index=None,
                    output_index=None,
                    output_symbol=symbol,
                    transformed=False,
                )
            )
            continue

        output_index = (input_index + effective_shift) % len(alphabet.symbols)
        output_symbol = alphabet.symbols[output_index]
        output_symbols.append(output_symbol)
        steps.append(
            ClassicalTransformStep(
                position=position,
                input_symbol=symbol,
                input_index=input_index,
                key_index=normalized_shift,
                output_index=output_index,
                output_symbol=output_symbol,
                transformed=True,
            )
        )

    return CaesarResult(
        operation="decrypt" if decrypt else "encrypt",
        text=text,
        output="".join(output_symbols),
        shift=shift,
        normalized_shift=normalized_shift,
        alphabet_name=alphabet.name,
        alphabet_size=len(alphabet.symbols),
        unknown_policy=unknown_policy,
        steps=tuple(steps),
    )


def caesar_encrypt(
    text: str,
    shift: int,
    alphabet: Alphabet,
    unknown_policy: UnknownSymbolPolicy = UnknownSymbolPolicy.PRESERVE,
) -> CaesarResult:
    """Encrypt text with a Caesar shift over the selected alphabet."""

    return _transform(text, shift, alphabet, unknown_policy, decrypt=False)


def caesar_decrypt(
    text: str,
    shift: int,
    alphabet: Alphabet,
    unknown_policy: UnknownSymbolPolicy = UnknownSymbolPolicy.PRESERVE,
) -> CaesarResult:
    """Decrypt text with a Caesar shift over the selected alphabet."""

    return _transform(text, shift, alphabet, unknown_policy, decrypt=True)


def caesar_table(shift: int, alphabet: Alphabet) -> tuple[CaesarTableEntry, ...]:
    """Return the full substitution table for one normalized Caesar shift."""

    normalized_shift = shift % len(alphabet.symbols)
    return tuple(
        CaesarTableEntry(
            input_index=index,
            input_symbol=symbol,
            output_index=(index + normalized_shift) % len(alphabet.symbols),
            output_symbol=alphabet.symbols[(index + normalized_shift) % len(alphabet.symbols)],
        )
        for index, symbol in enumerate(alphabet.symbols)
    )


def caesar_candidates(
    ciphertext: str,
    alphabet: Alphabet,
    unknown_policy: UnknownSymbolPolicy = UnknownSymbolPolicy.PRESERVE,
) -> tuple[CaesarCandidate, ...]:
    """Enumerate every candidate plaintext in the finite Caesar key space."""

    return tuple(
        CaesarCandidate(
            shift=shift,
            plaintext=caesar_decrypt(ciphertext, shift, alphabet, unknown_policy).output,
        )
        for shift in range(len(alphabet.symbols))
    )


def caesar_frequency(text: str, alphabet: Alphabet) -> FrequencyResult:
    """Count alphabet symbols without performing language-specific inference."""

    index_map = alphabet.index_map()
    counts = dict.fromkeys(alphabet.symbols, 0)
    unknown_count = 0
    for symbol in text:
        if symbol in index_map:
            counts[symbol] += 1
        else:
            unknown_count += 1

    total = sum(counts.values())
    highest = max(counts.values(), default=0)
    most_frequent = (
        tuple(symbol for symbol in alphabet.symbols if counts[symbol] == highest)
        if highest > 0
        else ()
    )
    entries = tuple(
        FrequencyEntry(
            symbol=symbol,
            count=counts[symbol],
            percentage=(100.0 * counts[symbol] / total) if total else 0.0,
        )
        for symbol in alphabet.symbols
    )
    return FrequencyResult(
        text=text,
        alphabet_name=alphabet.name,
        total_alphabet_symbols=total,
        unknown_symbol_count=unknown_count,
        most_frequent=most_frequent,
        entries=entries,
    )
