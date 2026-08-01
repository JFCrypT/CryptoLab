from __future__ import annotations

from cryptolab.labs.vernam_key_reuse import run_vernam_key_reuse_lab
from cryptolab.sequences.analysis import analyze_binary_sequence
from cryptolab.sequences.lfsr import (
    detect_lfsr_period,
    generate_lfsr,
    parse_feedback_polynomial,
    parse_seed,
)
from cryptolab.symmetric.vernam import vernam_decrypt, vernam_encrypt


def test_vernam_self_inverse_workflow() -> None:
    message = b"HELLO"
    key = bytes.fromhex("0011223344")
    ciphertext = bytes.fromhex(vernam_encrypt(message, key).output_hex)
    recovered = bytes.fromhex(vernam_decrypt(ciphertext, key).output_hex)
    assert recovered == message


def test_lfsr_generation_to_sequence_analysis_workflow() -> None:
    polynomial = parse_feedback_polynomial("x^3+x^2+1")
    seed = parse_seed("101", polynomial.degree)
    period = detect_lfsr_period(polynomial, seed)
    sequence = generate_lfsr(polynomial, seed, period.period).output
    analysis = analyze_binary_sequence(sequence)
    assert analysis.fundamental_period == period.period
    assert analysis.balanced
    assert all(item.value == -1 for item in analysis.autocorrelation[1:])


def test_controlled_vernam_lab_uses_same_xor_identity() -> None:
    result = run_vernam_key_reuse_lab(b"AB", b"CD", bytes.fromhex("0102"))
    assert result.identity_holds
    assert result.ciphertext_xor_hex == result.plaintext_xor_hex
