from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from cryptolab.sequences.lfsr import generate_lfsr, parse_feedback_polynomial, parse_seed
from cryptolab.symmetric.xor import xor_bytes


@given(st.binary(max_size=128), st.binary(max_size=128))
def test_xor_is_self_inverse(left: bytes, mask: bytes) -> None:
    size = min(len(left), len(mask))
    left = left[:size]
    mask = mask[:size]
    transformed = bytes.fromhex(xor_bytes(left, mask).output_hex)
    recovered = bytes.fromhex(xor_bytes(transformed, mask).output_hex)
    assert recovered == left


@given(st.integers(min_value=1, max_value=200))
def test_lfsr_generation_has_requested_length(length: int) -> None:
    polynomial = parse_feedback_polynomial("x^3+x^2+1")
    seed = parse_seed("101", polynomial.degree)
    assert len(generate_lfsr(polynomial, seed, length).output) == length
