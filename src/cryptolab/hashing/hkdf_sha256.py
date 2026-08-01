"""Library-backed HKDF-SHA-256 extraction and expansion."""

from __future__ import annotations

from dataclasses import dataclass
from hmac import digest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from cryptolab.exceptions import InputValidationError
from cryptolab.limits import MAX_HKDF_OUTPUT_BYTES

HKDF_SHA256_HASH_BYTES = 32


@dataclass(frozen=True, slots=True)
class HKDFResult:
    """Transparent HKDF-SHA-256 extract-and-expand result."""

    ikm_length: int
    salt_provided: bool
    effective_salt_hex: str
    info_hex: str
    prk_hex: str
    okm_hex: str
    output_length: int
    hash_algorithm: str
    library: str
    complete_derivation_matches: bool


def derive_hkdf_sha256(
    *,
    ikm: bytes,
    salt: bytes | None,
    info: bytes,
    length: int,
) -> HKDFResult:
    """Derive output keying material and expose the RFC 5869 stages."""

    if not ikm:
        raise InputValidationError("HKDF input keying material must not be empty.")
    if length < 1 or length > MAX_HKDF_OUTPUT_BYTES:
        raise InputValidationError(
            f"HKDF output length must be between 1 and {MAX_HKDF_OUTPUT_BYTES} bytes."
        )

    algorithm = hashes.SHA256()
    effective_salt = salt if salt is not None else bytes(HKDF_SHA256_HASH_BYTES)
    prk = digest(effective_salt, ikm, "sha256")
    okm = HKDFExpand(algorithm=algorithm, length=length, info=info).derive(prk)
    complete = HKDF(algorithm=algorithm, length=length, salt=salt, info=info).derive(ikm)
    matches = okm == complete
    if not matches:  # pragma: no cover
        raise RuntimeError("Internal HKDF extract-and-expand cross-check failed.")

    return HKDFResult(
        ikm_length=len(ikm),
        salt_provided=salt is not None,
        effective_salt_hex=effective_salt.hex(),
        info_hex=info.hex(),
        prk_hex=prk.hex(),
        okm_hex=okm.hex(),
        output_length=length,
        hash_algorithm="SHA-256",
        library="Python hmac + cryptography HKDF/HKDFExpand",
        complete_derivation_matches=matches,
    )
