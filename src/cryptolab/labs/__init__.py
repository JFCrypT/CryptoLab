"""Approved controlled cryptanalysis laboratories."""

from cryptolab.labs.caesar_brute_force import (
    CaesarBruteForceLabResult,
    run_caesar_brute_force_lab,
)
from cryptolab.labs.models import APPROVED_LABS, LabDescriptor
from cryptolab.labs.vernam_key_reuse import (
    VernamKeyReuseLabResult,
    run_vernam_key_reuse_lab,
)

__all__ = [
    "APPROVED_LABS",
    "CaesarBruteForceLabResult",
    "LabDescriptor",
    "VernamKeyReuseLabResult",
    "run_caesar_brute_force_lab",
    "run_vernam_key_reuse_lab",
]
