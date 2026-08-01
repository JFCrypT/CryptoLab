"""Controlled Caesar brute-force laboratory."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.classical.alphabet import Alphabet, UnknownSymbolPolicy
from cryptolab.classical.caesar import CaesarCandidate, caesar_candidates, caesar_frequency


@dataclass(frozen=True, slots=True)
class CaesarBruteForceLabResult:
    """Complete finite-key-space enumeration for a Caesar ciphertext."""

    identifier: str
    ciphertext: str
    alphabet_name: str
    key_space_size: int
    candidates: tuple[CaesarCandidate, ...]
    ciphertext_frequency_symbols: tuple[str, ...]
    violated_assumption: str
    security_effect: str
    mitigation: str


def run_caesar_brute_force_lab(
    ciphertext: str,
    alphabet: Alphabet,
    unknown_policy: UnknownSymbolPolicy = UnknownSymbolPolicy.PRESERVE,
) -> CaesarBruteForceLabResult:
    """Enumerate every Caesar key and record basic ciphertext-frequency information."""

    frequency = caesar_frequency(ciphertext, alphabet)
    candidates = caesar_candidates(ciphertext, alphabet, unknown_policy)
    return CaesarBruteForceLabResult(
        identifier="caesar-brute-force",
        ciphertext=ciphertext,
        alphabet_name=alphabet.name,
        key_space_size=len(alphabet.symbols),
        candidates=candidates,
        ciphertext_frequency_symbols=frequency.most_frequent,
        violated_assumption="The key space is too small to resist exhaustive enumeration.",
        security_effect="Every possible plaintext candidate can be generated immediately.",
        mitigation="Use a modern authenticated-encryption construction with a large key space.",
    )
