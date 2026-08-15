"""FIPS 203 ML-KEM parameter profiles and OpenSSL-backed operations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from cryptolab.exceptions import InputValidationError
from cryptolab.post_quantum.openssl_backend import (
    OpenSSLKeyPairMaterial,
    generate_key_pair,
    kem_decapsulate,
    kem_encapsulate,
)


class MLKEMParameterSet(StrEnum):
    """FIPS 203 parameter sets."""

    ML_KEM_512 = "ML-KEM-512"
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"


@dataclass(frozen=True, slots=True)
class MLKEMProfile:
    """Standardized raw ML-KEM sizes and security category."""

    parameter_set: str
    security_category: int
    public_key_bytes: int
    private_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int
    standard: str


@dataclass(frozen=True, slots=True)
class MLKEMEncapsulationResult:
    """One ML-KEM encapsulation."""

    parameter_set: str
    ciphertext_hex: str
    shared_secret_hex: str
    ciphertext_length_bytes: int
    shared_secret_length_bytes: int
    standard: str
    library: str


@dataclass(frozen=True, slots=True)
class MLKEMDecapsulationResult:
    """One ML-KEM decapsulation."""

    parameter_set: str
    ciphertext_hex: str
    shared_secret_hex: str
    ciphertext_length_bytes: int
    shared_secret_length_bytes: int
    standard: str
    library: str


_PROFILES = {
    MLKEMParameterSet.ML_KEM_512: MLKEMProfile("ML-KEM-512", 1, 800, 1632, 768, 32, "FIPS 203"),
    MLKEMParameterSet.ML_KEM_768: MLKEMProfile("ML-KEM-768", 3, 1184, 2400, 1088, 32, "FIPS 203"),
    MLKEMParameterSet.ML_KEM_1024: MLKEMProfile("ML-KEM-1024", 5, 1568, 3168, 1568, 32, "FIPS 203"),
}


def ml_kem_parameter_profiles() -> tuple[MLKEMProfile, ...]:
    """Return the three FIPS 203 parameter profiles."""

    return tuple(_PROFILES[value] for value in MLKEMParameterSet)


def ml_kem_profile(parameter_set: MLKEMParameterSet) -> MLKEMProfile:
    """Return one FIPS 203 profile."""

    return _PROFILES[parameter_set]


def generate_ml_kem_key_pair(
    parameter_set: MLKEMParameterSet,
) -> OpenSSLKeyPairMaterial:
    """Generate one ML-KEM key pair through OpenSSL 3.5 EVP."""

    return generate_key_pair(
        parameter_set.value,
        standard="FIPS 203",
        kind="kem",
    )


def ml_kem_encapsulate(
    parameter_set: MLKEMParameterSet,
    public_pem: bytes,
) -> MLKEMEncapsulationResult:
    """Encapsulate a shared secret with an ML-KEM public key."""

    profile = ml_kem_profile(parameter_set)
    ciphertext, shared_secret, library = kem_encapsulate(parameter_set.value, public_pem)
    if len(ciphertext) != profile.ciphertext_bytes:
        raise InputValidationError(
            f"{parameter_set.value} backend returned {len(ciphertext)} ciphertext bytes; "
            f"FIPS 203 requires {profile.ciphertext_bytes}."
        )
    if len(shared_secret) != profile.shared_secret_bytes:
        raise InputValidationError(
            f"{parameter_set.value} backend returned {len(shared_secret)} shared-secret bytes; "
            f"FIPS 203 requires {profile.shared_secret_bytes}."
        )
    return MLKEMEncapsulationResult(
        parameter_set=parameter_set.value,
        ciphertext_hex=ciphertext.hex(),
        shared_secret_hex=shared_secret.hex(),
        ciphertext_length_bytes=len(ciphertext),
        shared_secret_length_bytes=len(shared_secret),
        standard=profile.standard,
        library=library,
    )


def ml_kem_decapsulate(
    parameter_set: MLKEMParameterSet,
    private_pem: bytes,
    ciphertext: bytes,
) -> MLKEMDecapsulationResult:
    """Decapsulate an ML-KEM ciphertext with the matching private key."""

    profile = ml_kem_profile(parameter_set)
    if len(ciphertext) != profile.ciphertext_bytes:
        raise InputValidationError(
            f"{parameter_set.value} ciphertext must contain exactly "
            f"{profile.ciphertext_bytes} bytes."
        )
    shared_secret, library = kem_decapsulate(parameter_set.value, private_pem, ciphertext)
    if len(shared_secret) != profile.shared_secret_bytes:
        raise InputValidationError(
            f"{parameter_set.value} backend returned an unexpected shared-secret length."
        )
    return MLKEMDecapsulationResult(
        parameter_set=parameter_set.value,
        ciphertext_hex=ciphertext.hex(),
        shared_secret_hex=shared_secret.hex(),
        ciphertext_length_bytes=len(ciphertext),
        shared_secret_length_bytes=len(shared_secret),
        standard=profile.standard,
        library=library,
    )
