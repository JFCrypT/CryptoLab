"""FIPS 204 ML-DSA parameter profiles and OpenSSL-backed signatures."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from cryptolab.exceptions import InputValidationError
from cryptolab.post_quantum.openssl_backend import (
    OpenSSLKeyPairMaterial,
    generate_key_pair,
    sign_message,
    verify_message,
)


class MLDSAParameterSet(StrEnum):
    """FIPS 204 parameter sets."""

    ML_DSA_44 = "ML-DSA-44"
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"


@dataclass(frozen=True, slots=True)
class MLDSAProfile:
    """Standardized raw ML-DSA sizes and security category."""

    parameter_set: str
    security_category: int
    public_key_bytes: int
    private_key_bytes: int
    signature_bytes: int
    standard: str


@dataclass(frozen=True, slots=True)
class MLDSASignatureResult:
    """One FIPS 204 pure ML-DSA signature."""

    parameter_set: str
    message_hex: str
    context_hex: str
    signature_hex: str
    signature_length_bytes: int
    public_fingerprint_sha256: str
    hedged_signing: bool
    standard: str
    library: str


@dataclass(frozen=True, slots=True)
class MLDSAVerificationResult:
    """One FIPS 204 pure ML-DSA verification."""

    parameter_set: str
    message_hex: str
    context_hex: str
    signature_hex: str
    valid: bool
    standard: str
    library: str


_PROFILES = {
    MLDSAParameterSet.ML_DSA_44: MLDSAProfile("ML-DSA-44", 2, 1312, 2560, 2420, "FIPS 204"),
    MLDSAParameterSet.ML_DSA_65: MLDSAProfile("ML-DSA-65", 3, 1952, 4032, 3309, "FIPS 204"),
    MLDSAParameterSet.ML_DSA_87: MLDSAProfile("ML-DSA-87", 5, 2592, 4896, 4627, "FIPS 204"),
}


def ml_dsa_parameter_profiles() -> tuple[MLDSAProfile, ...]:
    """Return the three FIPS 204 parameter profiles."""

    return tuple(_PROFILES[value] for value in MLDSAParameterSet)


def ml_dsa_profile(parameter_set: MLDSAParameterSet) -> MLDSAProfile:
    """Return one FIPS 204 profile."""

    return _PROFILES[parameter_set]


def generate_ml_dsa_key_pair(parameter_set: MLDSAParameterSet) -> OpenSSLKeyPairMaterial:
    """Generate one ML-DSA key pair through OpenSSL 3.5 EVP."""

    return generate_key_pair(
        parameter_set.value,
        standard="FIPS 204",
        kind="signature-ml-dsa",
    )


def ml_dsa_sign(
    parameter_set: MLDSAParameterSet,
    private_pem: bytes,
    message: bytes,
    *,
    context: bytes = b"",
) -> MLDSASignatureResult:
    """Sign one message with pure ML-DSA and optional FIPS 204 context."""

    profile = ml_dsa_profile(parameter_set)
    signature, fingerprint, library = sign_message(
        parameter_set.value,
        private_pem,
        message,
        context=context,
        kind="signature-ml-dsa",
    )
    if len(signature) != profile.signature_bytes:
        raise InputValidationError(
            f"{parameter_set.value} backend returned {len(signature)} signature bytes; "
            f"FIPS 204 requires {profile.signature_bytes}."
        )
    return MLDSASignatureResult(
        parameter_set=parameter_set.value,
        message_hex=message.hex(),
        context_hex=context.hex(),
        signature_hex=signature.hex(),
        signature_length_bytes=len(signature),
        public_fingerprint_sha256=fingerprint,
        hedged_signing=True,
        standard=profile.standard,
        library=library,
    )


def ml_dsa_verify(
    parameter_set: MLDSAParameterSet,
    public_pem: bytes,
    message: bytes,
    signature: bytes,
    *,
    context: bytes = b"",
) -> MLDSAVerificationResult:
    """Verify one pure ML-DSA signature."""

    profile = ml_dsa_profile(parameter_set)
    if len(signature) != profile.signature_bytes:
        return MLDSAVerificationResult(
            parameter_set=parameter_set.value,
            message_hex=message.hex(),
            context_hex=context.hex(),
            signature_hex=signature.hex(),
            valid=False,
            standard=profile.standard,
            library="OpenSSL 3.5+ EVP",
        )
    valid, library = verify_message(
        parameter_set.value,
        public_pem,
        message,
        signature,
        context=context,
        kind="signature-ml-dsa",
    )
    return MLDSAVerificationResult(
        parameter_set=parameter_set.value,
        message_hex=message.hex(),
        context_hex=context.hex(),
        signature_hex=signature.hex(),
        valid=valid,
        standard=profile.standard,
        library=library,
    )
