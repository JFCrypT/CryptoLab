"""Educational classical cryptography implementations."""

from cryptolab.classical.alphabet import (
    Alphabet,
    UnknownSymbolPolicy,
    builtin_alphabet_names,
    load_alphabet_file,
    load_builtin_alphabet,
)
from cryptolab.classical.caesar import (
    CaesarCandidate,
    CaesarResult,
    CaesarTableEntry,
    FrequencyEntry,
    FrequencyResult,
    caesar_candidates,
    caesar_decrypt,
    caesar_encrypt,
    caesar_frequency,
    caesar_table,
)
from cryptolab.classical.polybius import (
    PolybiusGrid,
    PolybiusResult,
    build_polybius_grid,
    polybius_decrypt,
    polybius_encrypt,
)
from cryptolab.classical.vigenere import (
    VigenereAlignmentEntry,
    VigenereResult,
    vigenere_decrypt,
    vigenere_encrypt,
)

__all__ = [
    "Alphabet",
    "CaesarCandidate",
    "CaesarResult",
    "CaesarTableEntry",
    "FrequencyEntry",
    "FrequencyResult",
    "PolybiusGrid",
    "PolybiusResult",
    "UnknownSymbolPolicy",
    "VigenereAlignmentEntry",
    "VigenereResult",
    "build_polybius_grid",
    "builtin_alphabet_names",
    "caesar_candidates",
    "caesar_decrypt",
    "caesar_encrypt",
    "caesar_frequency",
    "caesar_table",
    "load_alphabet_file",
    "load_builtin_alphabet",
    "polybius_decrypt",
    "polybius_encrypt",
    "vigenere_decrypt",
    "vigenere_encrypt",
]
