"""Library-backed SHA-256 and SHA3-256 operations and comparisons."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha3_256, sha256
from hmac import compare_digest
from typing import TYPE_CHECKING, Protocol

from cryptolab.exceptions import InputError, InputValidationError
from cryptolab.limits import MAX_AVALANCHE_INPUT_BYTES

if TYPE_CHECKING:
    from pathlib import Path


HASH_DIGEST_BYTES = 32
HASH_DIGEST_BITS = HASH_DIGEST_BYTES * 8
FILE_HASH_CHUNK_BYTES = 64 * 1024


class HashAlgorithm(StrEnum):
    """Hash algorithms included in the initial CryptoLab scope."""

    SHA256 = "sha256"
    SHA3_256 = "sha3-256"


class _HashObject(Protocol):
    @property
    def digest_size(self) -> int:
        """Return the digest size in bytes."""
        ...

    @property
    def block_size(self) -> int:
        """Return the internal block size in bytes."""
        ...

    def update(self, data: bytes) -> None:
        """Add bytes to the hash state."""

    def digest(self) -> bytes:
        """Return the binary digest."""

    def hexdigest(self) -> str:
        """Return the hexadecimal digest."""


@dataclass(frozen=True, slots=True)
class HashResult:
    """One SHA-256 or SHA3-256 digest."""

    algorithm: HashAlgorithm
    digest_hex: str
    digest_size_bits: int
    input_length: int
    source_kind: str
    library: str


@dataclass(frozen=True, slots=True)
class DigestVerificationResult:
    """Result of comparing an expected digest with a computed digest."""

    algorithm: HashAlgorithm
    expected_digest_hex: str
    computed_digest_hex: str
    valid: bool
    input_length: int
    source_kind: str


@dataclass(frozen=True, slots=True)
class DigestByteDifference:
    """One byte of digest-level avalanche comparison."""

    index: int
    left_hex: str
    right_hex: str
    xor_hex: str
    changed_bits: int


@dataclass(frozen=True, slots=True)
class AvalancheResult:
    """Bit-difference analysis for two equal-length messages and their digests."""

    algorithm: HashAlgorithm
    input_length: int
    changed_input_bits: int
    left_digest_hex: str
    right_digest_hex: str
    digest_xor_hex: str
    changed_digest_bits: int
    digest_bits: int
    changed_digest_percentage: float
    byte_differences: tuple[DigestByteDifference, ...]


@dataclass(frozen=True, slots=True)
class HashProfile:
    """Contextual comparison data for one included hash function."""

    algorithm: str
    family: str
    digest_size: str
    internal_structure: str
    practical_api: str
    principal_note: str


@dataclass(frozen=True, slots=True)
class HashMACProfile:
    """Comparison data distinguishing unkeyed hashing from HMAC."""

    construction: str
    key_requirement: str
    primary_property: str
    typical_verification: str
    limitation: str


def _new_hash(algorithm: HashAlgorithm) -> _HashObject:
    if algorithm is HashAlgorithm.SHA256:
        return sha256()
    return sha3_256()


def _digest(data: bytes, algorithm: HashAlgorithm) -> bytes:
    hasher = _new_hash(algorithm)
    hasher.update(data)
    return hasher.digest()


def hash_bytes(
    data: bytes,
    algorithm: HashAlgorithm,
    *,
    source_kind: str = "bytes",
) -> HashResult:
    """Hash bytes using the selected established hashlib implementation."""

    digest = _digest(data, algorithm)
    return HashResult(
        algorithm=algorithm,
        digest_hex=digest.hex(),
        digest_size_bits=len(digest) * 8,
        input_length=len(data),
        source_kind=source_kind,
        library="Python hashlib",
    )


def hash_file(path: Path, algorithm: HashAlgorithm) -> HashResult:
    """Hash a file incrementally without loading the complete file into memory."""

    hasher = _new_hash(algorithm)
    total = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(FILE_HASH_CHUNK_BYTES):
                hasher.update(chunk)
                total += len(chunk)
    except OSError as error:
        raise InputError(f"Unable to read message file: {path}") from error
    return HashResult(
        algorithm=algorithm,
        digest_hex=hasher.hexdigest(),
        digest_size_bits=hasher.digest_size * 8,
        input_length=total,
        source_kind="file",
        library="Python hashlib",
    )


def verify_digest(
    *,
    computed: HashResult,
    expected_digest: bytes,
) -> DigestVerificationResult:
    """Compare a computed digest with an expected full-length digest."""

    if len(expected_digest) != HASH_DIGEST_BYTES:
        raise InputValidationError(
            f"Expected {computed.algorithm.value} digest must contain exactly "
            f"{HASH_DIGEST_BYTES} bytes."
        )
    computed_digest = bytes.fromhex(computed.digest_hex)
    return DigestVerificationResult(
        algorithm=computed.algorithm,
        expected_digest_hex=expected_digest.hex(),
        computed_digest_hex=computed.digest_hex,
        valid=compare_digest(computed_digest, expected_digest),
        input_length=computed.input_length,
        source_kind=computed.source_kind,
    )


def avalanche_effect(
    left: bytes,
    right: bytes,
    algorithm: HashAlgorithm,
) -> AvalancheResult:
    """Compare message and digest bit differences for an avalanche demonstration."""

    if len(left) != len(right):
        raise InputValidationError("Avalanche inputs must contain the same number of bytes.")
    if len(left) > MAX_AVALANCHE_INPUT_BYTES:
        raise InputValidationError(
            f"Avalanche inputs must not exceed {MAX_AVALANCHE_INPUT_BYTES} bytes."
        )
    if left == right:
        raise InputValidationError("Avalanche inputs must differ in at least one bit.")

    input_xor = bytes(a ^ b for a, b in zip(left, right, strict=True))
    changed_input_bits = sum(value.bit_count() for value in input_xor)
    left_digest = _digest(left, algorithm)
    right_digest = _digest(right, algorithm)
    digest_xor = bytes(a ^ b for a, b in zip(left_digest, right_digest, strict=True))
    differences = tuple(
        DigestByteDifference(
            index=index,
            left_hex=f"{left_byte:02x}",
            right_hex=f"{right_byte:02x}",
            xor_hex=f"{xor_byte:02x}",
            changed_bits=xor_byte.bit_count(),
        )
        for index, (left_byte, right_byte, xor_byte) in enumerate(
            zip(left_digest, right_digest, digest_xor, strict=True)
        )
    )
    changed_digest_bits = sum(item.changed_bits for item in differences)
    return AvalancheResult(
        algorithm=algorithm,
        input_length=len(left),
        changed_input_bits=changed_input_bits,
        left_digest_hex=left_digest.hex(),
        right_digest_hex=right_digest.hex(),
        digest_xor_hex=digest_xor.hex(),
        changed_digest_bits=changed_digest_bits,
        digest_bits=HASH_DIGEST_BITS,
        changed_digest_percentage=changed_digest_bits * 100.0 / HASH_DIGEST_BITS,
        byte_differences=differences,
    )


def hash_profiles() -> tuple[HashProfile, ...]:
    """Return a contextual SHA-256 and SHA3-256 comparison."""

    return (
        HashProfile(
            algorithm="SHA-256",
            family="SHA-2",
            digest_size="256 bits",
            internal_structure="Iterated compression over 512-bit message blocks",
            practical_api="hashlib.sha256",
            principal_note="Widely deployed; an unkeyed digest does not authenticate a sender",
        ),
        HashProfile(
            algorithm="SHA3-256",
            family="SHA-3",
            digest_size="256 bits",
            internal_structure="Sponge construction based on the Keccak permutation",
            practical_api="hashlib.sha3_256",
            principal_note="Different construction family; not a drop-in authentication mechanism",
        ),
    )


def hash_mac_profiles() -> tuple[HashMACProfile, ...]:
    """Return the required distinction between a hash function and HMAC."""

    return (
        HashMACProfile(
            construction="SHA-256 or SHA3-256 digest",
            key_requirement="No secret key",
            primary_property="Deterministic message fingerprint",
            typical_verification="Recompute the digest and compare",
            limitation="Anyone can recompute it; it does not authenticate a sender",
        ),
        HashMACProfile(
            construction="HMAC-SHA-256",
            key_requirement="Shared secret key",
            primary_property="Message integrity and symmetric authentication",
            typical_verification="Recompute with the shared key and compare in constant time",
            limitation="All verifiers share signing capability; it is not a digital signature",
        ),
    )
