from __future__ import annotations

from cryptolab.classical.alphabet import load_builtin_alphabet
from cryptolab.classical.caesar import caesar_candidates, caesar_encrypt
from cryptolab.classical.vigenere import vigenere_decrypt, vigenere_encrypt
from cryptolab.mathematics.algebra import GroupOperation, generated_subgroup, primitive_roots


def test_additive_group_and_caesar_shift_connection() -> None:
    alphabet = load_builtin_alphabet("latin-upper")
    subgroup = generated_subgroup(5, len(alphabet.symbols), GroupOperation.ADDITIVE)
    encrypted = caesar_encrypt("A", 5, alphabet)
    assert encrypted.output == alphabet.symbols[subgroup.elements[1]]


def test_caesar_candidate_enumeration_recovers_plaintext() -> None:
    alphabet = load_builtin_alphabet("latin-upper")
    ciphertext = caesar_encrypt("CRYPTOGRAPHY", 11, alphabet).output
    candidates = caesar_candidates(ciphertext, alphabet)
    assert candidates[11].plaintext == "CRYPTOGRAPHY"


def test_vigenere_round_trip_and_primitive_root_computation() -> None:
    alphabet = load_builtin_alphabet("latin-upper")
    encrypted = vigenere_encrypt("DISCRETE", "GROUP", alphabet)
    assert vigenere_decrypt(encrypted.output, "GROUP", alphabet).output == "DISCRETE"
    assert 3 in primitive_roots(17).generators
