from __future__ import annotations

from pathlib import Path

import pytest

from cryptolab.exceptions import InputError, InputValidationError
from cryptolab.hashing.hashes import (
    HashAlgorithm,
    avalanche_effect,
    hash_bytes,
    hash_file,
    hash_mac_profiles,
    hash_profiles,
    verify_digest,
)


def test_sha256_and_sha3_256_published_vectors() -> None:
    assert hash_bytes(b"abc", HashAlgorithm.SHA256).digest_hex == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert hash_bytes(b"abc", HashAlgorithm.SHA3_256).digest_hex == (
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    )
    assert hash_bytes(b"", HashAlgorithm.SHA256).digest_hex == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert hash_bytes(b"", HashAlgorithm.SHA3_256).digest_hex == (
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    )


def test_hash_file_streaming_matches_bytes(tmp_path: Path) -> None:
    data = bytes(range(256)) * 1000
    path = tmp_path / "payload.bin"
    path.write_bytes(data)
    file_result = hash_file(path, HashAlgorithm.SHA256)
    byte_result = hash_bytes(data, HashAlgorithm.SHA256)
    assert file_result.digest_hex == byte_result.digest_hex
    assert file_result.input_length == len(data)
    assert file_result.source_kind == "file"


def test_hash_file_reports_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="Unable to read message file"):
        hash_file(tmp_path / "missing.bin", HashAlgorithm.SHA256)


def test_digest_verification_and_length_validation() -> None:
    computed = hash_bytes(b"abc", HashAlgorithm.SHA256, source_kind="text")
    valid = verify_digest(computed=computed, expected_digest=bytes.fromhex(computed.digest_hex))
    invalid = verify_digest(computed=computed, expected_digest=bytes(32))
    assert valid.valid
    assert not invalid.valid
    assert valid.source_kind == "text"
    with pytest.raises(InputValidationError, match="exactly 32 bytes"):
        verify_digest(computed=computed, expected_digest=bytes(31))


def test_avalanche_effect_reports_bit_differences() -> None:
    result = avalanche_effect(b"abc", b"abd", HashAlgorithm.SHA256)
    assert result.changed_input_bits == 3
    assert result.digest_bits == 256
    assert 0 < result.changed_digest_bits <= 256
    assert len(result.byte_differences) == 32
    assert sum(item.changed_bits for item in result.byte_differences) == result.changed_digest_bits
    assert bytes.fromhex(result.digest_xor_hex)


def test_avalanche_validation() -> None:
    with pytest.raises(InputValidationError, match="same number of bytes"):
        avalanche_effect(b"a", b"bb", HashAlgorithm.SHA256)
    with pytest.raises(InputValidationError, match="differ"):
        avalanche_effect(b"same", b"same", HashAlgorithm.SHA3_256)


def test_hash_comparison_profiles_cover_required_distinctions() -> None:
    profiles = hash_profiles()
    assert {item.algorithm for item in profiles} == {"SHA-256", "SHA3-256"}
    assert {item.family for item in profiles} == {"SHA-2", "SHA-3"}
    assert all(item.digest_size == "256 bits" for item in profiles)
    mac_profiles = hash_mac_profiles()
    assert mac_profiles[0].key_requirement == "No secret key"
    assert mac_profiles[1].key_requirement == "Shared secret key"
