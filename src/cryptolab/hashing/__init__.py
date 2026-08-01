"""Hashing, message authentication, and key derivation primitives."""

from cryptolab.hashing.hashes import (
    AvalancheResult,
    DigestVerificationResult,
    HashAlgorithm,
    HashResult,
    avalanche_effect,
    hash_bytes,
    hash_file,
    hash_mac_profiles,
    hash_profiles,
    verify_digest,
)
from cryptolab.hashing.hkdf_sha256 import HKDFResult, derive_hkdf_sha256
from cryptolab.hashing.hmac_sha256 import (
    HMACResult,
    HMACVerificationResult,
    generate_hmac_sha256,
    verify_hmac_sha256,
)

__all__ = [
    "AvalancheResult",
    "DigestVerificationResult",
    "HKDFResult",
    "HMACResult",
    "HMACVerificationResult",
    "HashAlgorithm",
    "HashResult",
    "avalanche_effect",
    "derive_hkdf_sha256",
    "generate_hmac_sha256",
    "hash_bytes",
    "hash_file",
    "hash_mac_profiles",
    "hash_profiles",
    "verify_digest",
    "verify_hmac_sha256",
]
