"""Approved controlled cryptanalysis laboratories."""

from cryptolab.labs.caesar_brute_force import (
    CaesarBruteForceLabResult,
    run_caesar_brute_force_lab,
)
from cryptolab.labs.ecb_pattern_leakage import (
    ECBPatternLeakageResult,
    run_ecb_pattern_leakage_lab,
)
from cryptolab.labs.models import APPROVED_LABS, LabDescriptor
from cryptolab.labs.vernam_key_reuse import (
    VernamKeyReuseLabResult,
    run_vernam_key_reuse_lab,
)

__all__ = [
    "APPROVED_LABS",
    "CaesarBruteForceLabResult",
    "ECBPatternLeakageResult",
    "LabDescriptor",
    "VernamKeyReuseLabResult",
    "run_caesar_brute_force_lab",
    "run_ecb_pattern_leakage_lab",
    "run_vernam_key_reuse_lab",
]
