from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from cryptolab.classical.alphabet import load_builtin_alphabet
from cryptolab.classical.caesar import caesar_decrypt, caesar_encrypt
from cryptolab.classical.polybius import polybius_decrypt, polybius_encrypt
from cryptolab.classical.vigenere import vigenere_decrypt, vigenere_encrypt

ALPHABET = load_builtin_alphabet("latin-upper")
ALPHABET_TEXT = st.text(alphabet=[*ALPHABET.symbols, " ", "!"], max_size=60)
KEYS = st.text(alphabet=list(ALPHABET.symbols), min_size=1, max_size=12)


@given(text=ALPHABET_TEXT, shift=st.integers(min_value=-10_000, max_value=10_000))
def test_caesar_round_trip_property(text: str, shift: int) -> None:
    encrypted = caesar_encrypt(text, shift, ALPHABET)
    assert caesar_decrypt(encrypted.output, shift, ALPHABET).output == text


@given(text=ALPHABET_TEXT, key=KEYS)
def test_vigenere_round_trip_property(text: str, key: str) -> None:
    encrypted = vigenere_encrypt(text, key, ALPHABET)
    assert vigenere_decrypt(encrypted.output, key, ALPHABET).output == text


@given(text=ALPHABET_TEXT)
def test_polybius_round_trip_property(text: str) -> None:
    encrypted = polybius_encrypt(text, ALPHABET)
    assert polybius_decrypt(encrypted.output_text, ALPHABET).output_text == text
