"""Library-backed HMAC-SHA-256 generation and verification."""

from __future__ import annotations

from dataclasses import dataclass
from hmac import compare_digest, digest

from cryptolab.exceptions import InputValidationError

HMAC_SHA256_TAG_BYTES = 32


@dataclass(frozen=True, slots=True)
class HMACResult:
    """One full-length HMAC-SHA-256 tag."""

    tag_hex: str
    key_length: int
    message_length: int
    library: str


@dataclass(frozen=True, slots=True)
class HMACVerificationResult:
    """Result of full-length HMAC-SHA-256 verification."""

    expected_tag_hex: str
    computed_tag_hex: str
    valid: bool
    key_length: int
    message_length: int


def _validate_key(key: bytes) -> None:
    if not key:
        raise InputValidationError("HMAC-SHA-256 key must not be empty.")


def generate_hmac_sha256(key: bytes, message: bytes) -> HMACResult:
    """Generate a full-length HMAC-SHA-256 tag with Python's hmac module."""

    _validate_key(key)
    tag = digest(key, message, "sha256")
    return HMACResult(
        tag_hex=tag.hex(),
        key_length=len(key),
        message_length=len(message),
        library="Python hmac",
    )


def verify_hmac_sha256(key: bytes, message: bytes, expected_tag: bytes) -> HMACVerificationResult:
    """Verify a full-length HMAC-SHA-256 tag using constant-time comparison."""

    _validate_key(key)
    if len(expected_tag) != HMAC_SHA256_TAG_BYTES:
        raise InputValidationError(
            f"HMAC-SHA-256 tag must contain exactly {HMAC_SHA256_TAG_BYTES} bytes."
        )
    computed = digest(key, message, "sha256")
    return HMACVerificationResult(
        expected_tag_hex=expected_tag.hex(),
        computed_tag_hex=computed.hex(),
        valid=compare_digest(computed, expected_tag),
        key_length=len(key),
        message_length=len(message),
    )
