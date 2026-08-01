from __future__ import annotations

from cryptolab.classical.alphabet import load_builtin_alphabet
from cryptolab.labs.caesar_brute_force import run_caesar_brute_force_lab
from cryptolab.labs.models import APPROVED_LABS
from cryptolab.labs.vernam_key_reuse import run_vernam_key_reuse_lab


def test_lab_registry_contains_exactly_four_approved_labs() -> None:
    assert [lab.identifier for lab in APPROVED_LABS] == [
        "caesar-brute-force",
        "vernam-key-reuse",
        "ecb-pattern-leakage",
        "dh-man-in-the-middle",
    ]
    assert [lab.status for lab in APPROVED_LABS] == [
        "implemented",
        "implemented",
        "implemented",
        "planned",
    ]


def test_caesar_brute_force_lab_reuses_caesar_module() -> None:
    result = run_caesar_brute_force_lab("KHOOR", load_builtin_alphabet("latin-upper"))
    assert result.key_space_size == 26
    assert result.candidates[3].plaintext == "HELLO"
    assert result.identifier == "caesar-brute-force"
    assert result.mitigation


def test_vernam_key_reuse_identity() -> None:
    result = run_vernam_key_reuse_lab(
        bytes.fromhex("beca"),
        bytes.fromhex("bcee"),
        bytes.fromhex("fe12"),
    )
    assert result.identity_holds
    assert result.ciphertext_xor_hex == result.plaintext_xor_hex
    assert result.identifier == "vernam-key-reuse"
