"""Educational and library-backed symmetric cryptography modules."""

from cryptolab.symmetric.modern import (
    AEADProfile,
    AESMode,
    AESModeProfile,
    ModernCipherResult,
    PaddingMode,
    aead_profiles,
    aes_decrypt,
    aes_encrypt,
    aes_mode_profiles,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)
from cryptolab.symmetric.otp import OTPRequirement, otp_requirements
from cryptolab.symmetric.vernam import VernamResult, vernam_decrypt, vernam_encrypt
from cryptolab.symmetric.xor import ByteXORResult, xor_bits, xor_bytes, xor_truth_table

__all__ = [
    "AEADProfile",
    "AESMode",
    "AESModeProfile",
    "ByteXORResult",
    "ModernCipherResult",
    "OTPRequirement",
    "PaddingMode",
    "VernamResult",
    "aead_profiles",
    "aes_decrypt",
    "aes_encrypt",
    "aes_mode_profiles",
    "chacha20_poly1305_decrypt",
    "chacha20_poly1305_encrypt",
    "otp_requirements",
    "vernam_decrypt",
    "vernam_encrypt",
    "xor_bits",
    "xor_bytes",
    "xor_truth_table",
]
