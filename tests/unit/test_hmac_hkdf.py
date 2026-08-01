from __future__ import annotations

import pytest

from cryptolab.exceptions import InputValidationError
from cryptolab.hashing.hkdf_sha256 import derive_hkdf_sha256
from cryptolab.hashing.hmac_sha256 import generate_hmac_sha256, verify_hmac_sha256


def test_rfc_4231_hmac_sha256_vectors() -> None:
    case_one = generate_hmac_sha256(bytes.fromhex("0b" * 20), b"Hi There")
    assert case_one.tag_hex == ("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    case_two = generate_hmac_sha256(b"Jefe", b"what do ya want for nothing?")
    assert case_two.tag_hex == ("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")


def test_hmac_verification_and_validation() -> None:
    generated = generate_hmac_sha256(b"key", b"message")
    valid = verify_hmac_sha256(b"key", b"message", bytes.fromhex(generated.tag_hex))
    invalid = verify_hmac_sha256(b"key", b"changed", bytes.fromhex(generated.tag_hex))
    assert valid.valid
    assert not invalid.valid
    with pytest.raises(InputValidationError, match="must not be empty"):
        generate_hmac_sha256(b"", b"message")
    with pytest.raises(InputValidationError, match="exactly 32 bytes"):
        verify_hmac_sha256(b"key", b"message", bytes(16))


def test_rfc_5869_hkdf_sha256_case_one() -> None:
    result = derive_hkdf_sha256(
        ikm=bytes.fromhex("0b" * 22),
        salt=bytes.fromhex("000102030405060708090a0b0c"),
        info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        length=42,
    )
    assert result.prk_hex == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    assert result.okm_hex == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    assert result.complete_derivation_matches


def test_rfc_5869_hkdf_sha256_default_salt_case() -> None:
    result = derive_hkdf_sha256(ikm=bytes.fromhex("0b" * 22), salt=None, info=b"", length=42)
    assert result.prk_hex == "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    assert result.okm_hex == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    )
    assert result.effective_salt_hex == "00" * 32
    assert not result.salt_provided


def test_hkdf_length_and_input_validation() -> None:
    with pytest.raises(InputValidationError, match="must not be empty"):
        derive_hkdf_sha256(ikm=b"", salt=None, info=b"", length=32)
    with pytest.raises(InputValidationError, match="between 1 and 8160"):
        derive_hkdf_sha256(ikm=b"ikm", salt=None, info=b"", length=0)
    with pytest.raises(InputValidationError, match="between 1 and 8160"):
        derive_hkdf_sha256(ikm=b"ikm", salt=None, info=b"", length=8161)
