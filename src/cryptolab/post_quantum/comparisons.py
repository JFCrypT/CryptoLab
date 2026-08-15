"""Contextual comparisons for classical and standardized post-quantum primitives."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PQCComparisonProfile:
    """One comparison row used by post-quantum CLI tables."""

    construction: str
    role: str
    family: str
    standard: str
    quantum_status: str
    principal_tradeoff: str


def post_quantum_key_establishment_profiles() -> tuple[PQCComparisonProfile, ...]:
    """Compare classical DH/X25519 with standardized ML-KEM."""

    return (
        PQCComparisonProfile(
            "Finite-field Diffie-Hellman",
            "key agreement",
            "discrete logarithm",
            "classical construction",
            "not post-quantum",
            "educational transparency; large classical groups",
        ),
        PQCComparisonProfile(
            "X25519",
            "key agreement",
            "elliptic-curve discrete logarithm",
            "RFC 7748",
            "not post-quantum",
            "compact mature keys; vulnerable to a large-scale quantum computer",
        ),
        PQCComparisonProfile(
            "ML-KEM",
            "key encapsulation",
            "module lattices / Module-LWE",
            "FIPS 203",
            "post-quantum design",
            "larger public keys and ciphertexts than X25519",
        ),
    )


def post_quantum_signature_profiles() -> tuple[PQCComparisonProfile, ...]:
    """Compare current classical signatures with NIST-standardized PQC signatures."""

    return (
        PQCComparisonProfile(
            "RSA-PSS",
            "digital signature",
            "integer factorization",
            "RFC 8017",
            "not post-quantum",
            "large classical keys and signatures",
        ),
        PQCComparisonProfile(
            "Ed25519",
            "digital signature",
            "elliptic-curve discrete logarithm",
            "RFC 8032",
            "not post-quantum",
            "compact and mature; vulnerable to a large-scale quantum computer",
        ),
        PQCComparisonProfile(
            "ML-DSA",
            "digital signature",
            "module lattices",
            "FIPS 204",
            "post-quantum design",
            "larger keys and signatures than Ed25519",
        ),
        PQCComparisonProfile(
            "SLH-DSA",
            "digital signature",
            "stateless hash-based signatures",
            "FIPS 205",
            "post-quantum design",
            "very large signatures; diversified assumptions",
        ),
    )


def classical_post_quantum_profiles() -> tuple[PQCComparisonProfile, ...]:
    """Summarize the 1.1.0 classical/PQC boundary."""

    return post_quantum_key_establishment_profiles() + post_quantum_signature_profiles()[1:]
