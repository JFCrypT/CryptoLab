from __future__ import annotations

import pytest

from cryptolab.classical.alphabet import UnknownSymbolPolicy, load_builtin_alphabet
from cryptolab.classical.caesar import (
    caesar_candidates,
    caesar_decrypt,
    caesar_encrypt,
    caesar_frequency,
    caesar_table,
)
from cryptolab.exceptions import InputValidationError

LATIN = load_builtin_alphabet("latin-upper")
SPANISH = load_builtin_alphabet("spanish-upper")


def test_caesar_round_trip_positive_and_negative_shifts() -> None:
    for shift in (9, -9, 0, 53):
        encrypted = caesar_encrypt("PARABOLOIDE", shift, SPANISH)
        decrypted = caesar_decrypt(encrypted.output, shift, SPANISH)
        assert decrypted.output == "PARABOLOIDE"
        assert encrypted.normalized_shift == shift % 27


def test_caesar_unknown_symbol_policies() -> None:
    preserved = caesar_encrypt("HELLO WORLD!", 3, LATIN)
    assert preserved.output == "KHOOR ZRUOG!"
    assert not preserved.steps[5].transformed

    with pytest.raises(InputValidationError, match="position 5"):
        caesar_encrypt("HELLO WORLD", 3, LATIN, UnknownSymbolPolicy.REJECT)


def test_caesar_table_and_candidates() -> None:
    table = caesar_table(3, LATIN)
    assert table[0].output_symbol == "D"
    assert table[-1].output_symbol == "C"

    candidates = caesar_candidates("KHOOR", LATIN)
    assert len(candidates) == 26
    assert candidates[3].plaintext == "HELLO"


def test_caesar_frequency_counts_only_alphabet_symbols() -> None:
    result = caesar_frequency("ABRACADABRA!", LATIN)
    assert result.total_alphabet_symbols == 11
    assert result.unknown_symbol_count == 1
    assert result.most_frequent == ("A",)
    entry_a = next(entry for entry in result.entries if entry.symbol == "A")
    assert entry_a.count == 5
    assert round(entry_a.percentage, 2) == 45.45


def test_empty_frequency_input() -> None:
    result = caesar_frequency("...", LATIN)
    assert result.total_alphabet_symbols == 0
    assert result.most_frequent == ()
    assert all(entry.percentage == 0.0 for entry in result.entries)
