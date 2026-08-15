"""FIPS 205 SLH-DSA parameter profiles and OpenSSL-backed signatures."""

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


class SLHDSAParameterSet(StrEnum):
    """Twelve parameter sets approved by FIPS 205."""

    SHA2_128S = "SLH-DSA-SHA2-128s"
    SHA2_128F = "SLH-DSA-SHA2-128f"
    SHA2_192S = "SLH-DSA-SHA2-192s"
    SHA2_192F = "SLH-DSA-SHA2-192f"
    SHA2_256S = "SLH-DSA-SHA2-256s"
    SHA2_256F = "SLH-DSA-SHA2-256f"
    SHAKE_128S = "SLH-DSA-SHAKE-128s"
    SHAKE_128F = "SLH-DSA-SHAKE-128f"
    SHAKE_192S = "SLH-DSA-SHAKE-192s"
    SHAKE_192F = "SLH-DSA-SHAKE-192f"
    SHAKE_256S = "SLH-DSA-SHAKE-256s"
    SHAKE_256F = "SLH-DSA-SHAKE-256f"


@dataclass(frozen=True, slots=True)
class SLHDSAProfile:
    """FIPS 205 raw sizes, hash family, and security category."""

    parameter_set: str
    hash_family: str
    optimization: str
    security_category: int
    public_key_bytes: int
    private_key_bytes: int
    signature_bytes: int
    standard: str


@dataclass(frozen=True, slots=True)
class SLHDSASignatureResult:
    """One FIPS 205 pure SLH-DSA signature."""

    parameter_set: str
    message_hex: str
    context_hex: str
    signature_hex: str
    signature_length_bytes: int
    public_fingerprint_sha256: str
    standard: str
    library: str


@dataclass(frozen=True, slots=True)
class SLHDSAVerificationResult:
    """One FIPS 205 pure SLH-DSA verification."""

    parameter_set: str
    message_hex: str
    context_hex: str
    signature_hex: str
    valid: bool
    standard: str
    library: str


def _profile(
    parameter_set: str,
    hash_family: str,
    optimization: str,
    sizes: tuple[int, int, int, int],
) -> SLHDSAProfile:
    category, public_key_bytes, private_key_bytes, signature_bytes = sizes
    return SLHDSAProfile(
        parameter_set=parameter_set,
        hash_family=hash_family,
        optimization=optimization,
        security_category=category,
        public_key_bytes=public_key_bytes,
        private_key_bytes=private_key_bytes,
        signature_bytes=signature_bytes,
        standard="FIPS 205",
    )


_PROFILES = {
    SLHDSAParameterSet.SHA2_128S: _profile(
        "SLH-DSA-SHA2-128s", "SHA-2", "small", (1, 32, 64, 7856)
    ),
    SLHDSAParameterSet.SHA2_128F: _profile(
        "SLH-DSA-SHA2-128f", "SHA-2", "fast", (1, 32, 64, 17088)
    ),
    SLHDSAParameterSet.SHA2_192S: _profile(
        "SLH-DSA-SHA2-192s", "SHA-2", "small", (3, 48, 96, 16224)
    ),
    SLHDSAParameterSet.SHA2_192F: _profile(
        "SLH-DSA-SHA2-192f", "SHA-2", "fast", (3, 48, 96, 35664)
    ),
    SLHDSAParameterSet.SHA2_256S: _profile(
        "SLH-DSA-SHA2-256s", "SHA-2", "small", (5, 64, 128, 29792)
    ),
    SLHDSAParameterSet.SHA2_256F: _profile(
        "SLH-DSA-SHA2-256f", "SHA-2", "fast", (5, 64, 128, 49856)
    ),
    SLHDSAParameterSet.SHAKE_128S: _profile(
        "SLH-DSA-SHAKE-128s", "SHAKE", "small", (1, 32, 64, 7856)
    ),
    SLHDSAParameterSet.SHAKE_128F: _profile(
        "SLH-DSA-SHAKE-128f", "SHAKE", "fast", (1, 32, 64, 17088)
    ),
    SLHDSAParameterSet.SHAKE_192S: _profile(
        "SLH-DSA-SHAKE-192s", "SHAKE", "small", (3, 48, 96, 16224)
    ),
    SLHDSAParameterSet.SHAKE_192F: _profile(
        "SLH-DSA-SHAKE-192f", "SHAKE", "fast", (3, 48, 96, 35664)
    ),
    SLHDSAParameterSet.SHAKE_256S: _profile(
        "SLH-DSA-SHAKE-256s", "SHAKE", "small", (5, 64, 128, 29792)
    ),
    SLHDSAParameterSet.SHAKE_256F: _profile(
        "SLH-DSA-SHAKE-256f", "SHAKE", "fast", (5, 64, 128, 49856)
    ),
}


def slh_dsa_parameter_profiles() -> tuple[SLHDSAProfile, ...]:
    """Return all twelve FIPS 205 parameter profiles."""

    return tuple(_PROFILES[value] for value in SLHDSAParameterSet)


def slh_dsa_profile(parameter_set: SLHDSAParameterSet) -> SLHDSAProfile:
    """Return one FIPS 205 profile."""

    return _PROFILES[parameter_set]


def generate_slh_dsa_key_pair(parameter_set: SLHDSAParameterSet) -> OpenSSLKeyPairMaterial:
    """Generate one SLH-DSA key pair through OpenSSL 3.5 EVP."""

    return generate_key_pair(
        parameter_set.value,
        standard="FIPS 205",
        kind="signature-slh-dsa",
    )


def slh_dsa_sign(
    parameter_set: SLHDSAParameterSet,
    private_pem: bytes,
    message: bytes,
    *,
    context: bytes = b"",
) -> SLHDSASignatureResult:
    """Sign one message with pure SLH-DSA and optional FIPS 205 context."""

    profile = slh_dsa_profile(parameter_set)
    signature, fingerprint, library = sign_message(
        parameter_set.value,
        private_pem,
        message,
        context=context,
        kind="signature-slh-dsa",
    )
    if len(signature) != profile.signature_bytes:
        raise InputValidationError(
            f"{parameter_set.value} backend returned {len(signature)} signature bytes; "
            f"FIPS 205 requires {profile.signature_bytes}."
        )
    return SLHDSASignatureResult(
        parameter_set=parameter_set.value,
        message_hex=message.hex(),
        context_hex=context.hex(),
        signature_hex=signature.hex(),
        signature_length_bytes=len(signature),
        public_fingerprint_sha256=fingerprint,
        standard=profile.standard,
        library=library,
    )


def slh_dsa_verify(
    parameter_set: SLHDSAParameterSet,
    public_pem: bytes,
    message: bytes,
    signature: bytes,
    *,
    context: bytes = b"",
) -> SLHDSAVerificationResult:
    """Verify one pure SLH-DSA signature."""

    profile = slh_dsa_profile(parameter_set)
    if len(signature) != profile.signature_bytes:
        return SLHDSAVerificationResult(
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
        kind="signature-slh-dsa",
    )
    return SLHDSAVerificationResult(
        parameter_set=parameter_set.value,
        message_hex=message.hex(),
        context_hex=context.hex(),
        signature_hex=signature.hex(),
        valid=valid,
        standard=profile.standard,
        library=library,
    )
