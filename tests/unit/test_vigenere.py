from __future__ import annotations

import pytest

from cryptolab.classical.alphabet import UnknownSymbolPolicy, load_builtin_alphabet
from cryptolab.classical.vigenere import vigenere_decrypt, vigenere_encrypt
from cryptolab.exceptions import InputValidationError

LATIN = load_builtin_alphabet("latin-upper")
SPANISH = load_builtin_alphabet("spanish-upper")


def test_vigenere_standard_vector() -> None:
    encrypted = vigenere_encrypt("ATTACKATDAWN", "LEMON", LATIN)
    assert encrypted.output == "LXFOPVEFRNHR"
    assert vigenere_decrypt(encrypted.output, "LEMON", LATIN).output == "ATTACKATDAWN"


def test_vigenere_spanish_alphabet_round_trip() -> None:
    encrypted = vigenere_encrypt("ISOMORFISMO", "AUTHR", SPANISH)
    assert vigenere_decrypt(encrypted.output, "AUTHR", SPANISH).output == "ISOMORFISMO"


def test_vigenere_key_skips_preserved_symbols() -> None:
    encrypted = vigenere_encrypt("A A", "BC", LATIN)
    assert encrypted.output == "B C"
    assert encrypted.alignment[1].key_position is None
    assert encrypted.alignment[2].key_position == 1


def test_vigenere_rejects_invalid_key_or_symbol() -> None:
    with pytest.raises(InputValidationError, match="must not be empty"):
        vigenere_encrypt("ABC", "", LATIN)
    with pytest.raises(InputValidationError, match="Key symbol"):
        vigenere_encrypt("ABC", "A?", LATIN)
    with pytest.raises(InputValidationError, match="position 1"):
        vigenere_encrypt("A A", "KEY", LATIN, UnknownSymbolPolicy.REJECT)
