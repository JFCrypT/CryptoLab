from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from cryptolab.hashing.hashes import HashAlgorithm, avalanche_effect, hash_bytes
from cryptolab.hashing.hkdf_sha256 import derive_hkdf_sha256
from cryptolab.hashing.hmac_sha256 import generate_hmac_sha256, verify_hmac_sha256


@given(data=st.binary(max_size=512))
def test_hashes_are_deterministic_and_fixed_length(data: bytes) -> None:
    for algorithm in HashAlgorithm:
        first = hash_bytes(data, algorithm)
        second = hash_bytes(data, algorithm)
        assert first.digest_hex == second.digest_hex
        assert len(bytes.fromhex(first.digest_hex)) == 32


@given(
    left=st.binary(min_size=1, max_size=64),
    mask=st.integers(min_value=1, max_value=255),
)
def test_avalanche_accounting_is_consistent(left: bytes, mask: int) -> None:
    right = bytes([left[0] ^ mask]) + left[1:]
    result = avalanche_effect(left, right, HashAlgorithm.SHA256)
    assert result.changed_input_bits == mask.bit_count()
    assert result.changed_digest_bits == sum(item.changed_bits for item in result.byte_differences)
    assert 0 <= result.changed_digest_percentage <= 100


@given(
    key=st.binary(min_size=1, max_size=128),
    message=st.binary(max_size=512),
)
def test_hmac_round_trip_property(key: bytes, message: bytes) -> None:
    generated = generate_hmac_sha256(key, message)
    verified = verify_hmac_sha256(key, message, bytes.fromhex(generated.tag_hex))
    assert verified.valid


@given(
    ikm=st.binary(min_size=1, max_size=128),
    salt=st.one_of(st.none(), st.binary(max_size=64)),
    info=st.binary(max_size=64),
    length=st.integers(min_value=1, max_value=128),
)
def test_hkdf_is_deterministic_and_respects_length(
    ikm: bytes,
    salt: bytes | None,
    info: bytes,
    length: int,
) -> None:
    first = derive_hkdf_sha256(ikm=ikm, salt=salt, info=info, length=length)
    second = derive_hkdf_sha256(ikm=ikm, salt=salt, info=info, length=length)
    assert first.okm_hex == second.okm_hex
    assert len(bytes.fromhex(first.okm_hex)) == length
