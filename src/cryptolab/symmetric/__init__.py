"""Educational symmetric constructions implemented transparently by CryptoLab."""

from cryptolab.symmetric.otp import OTPRequirement, otp_requirements
from cryptolab.symmetric.vernam import VernamResult, vernam_decrypt, vernam_encrypt
from cryptolab.symmetric.xor import (
    BitXORResult,
    ByteXORResult,
    XORTruthRow,
    xor_bits,
    xor_bytes,
    xor_truth_table,
)

__all__ = [
    "BitXORResult",
    "ByteXORResult",
    "OTPRequirement",
    "VernamResult",
    "XORTruthRow",
    "otp_requirements",
    "vernam_decrypt",
    "vernam_encrypt",
    "xor_bits",
    "xor_bytes",
    "xor_truth_table",
]
