from __future__ import annotations

import pytest

from cryptolab.exceptions import (
    InputValidationError,
    MathematicalDomainError,
    ResourceLimitError,
)
from cryptolab.public_key.rsa_educational import (
    build_educational_rsa_key,
    bytes_to_integer,
    generate_educational_rsa_key,
    integer_to_bytes,
    textbook_rsa_decrypt,
    textbook_rsa_encrypt,
)


def test_classic_educational_rsa_example() -> None:
    key = build_educational_rsa_key(61, 53, 17)
    assert key.n == 3233
    assert key.phi == 3120
    assert key.carmichael == 780
    assert key.d == 2753
    assert key.d_carmichael == 413
    assert key.dp == 53
    assert key.dq == 49
    assert key.q_inverse_mod_p == 38
    encrypted = textbook_rsa_encrypt(65, key)
    assert encrypted.output_value == 2790
    assert encrypted.deterministic
    decrypted = textbook_rsa_decrypt(encrypted.output_value, key)
    assert decrypted.plaintext == 65
    assert decrypted.standard_plaintext == 65
    assert decrypted.crt_plaintext == 65
    assert decrypted.crt_matches_standard


def test_educational_key_validation() -> None:
    with pytest.raises(MathematicalDomainError, match="p must be prime"):
        build_educational_rsa_key(60, 53, 17)
    with pytest.raises(MathematicalDomainError, match="distinct"):
        build_educational_rsa_key(61, 61, 17)
    with pytest.raises(MathematicalDomainError, match=r"1 < e < phi\(n\)"):
        build_educational_rsa_key(61, 53, 1)
    with pytest.raises(MathematicalDomainError, match=r"gcd\(e, phi\(n\)\)"):
        build_educational_rsa_key(61, 53, 15)
    with pytest.raises(ResourceLimitError, match="20 bits"):
        build_educational_rsa_key(2_147_483_647, 53, 17)


def test_textbook_rsa_representative_bounds() -> None:
    key = build_educational_rsa_key(61, 53, 17)
    with pytest.raises(MathematicalDomainError, match="0 <= message < n"):
        textbook_rsa_encrypt(key.n, key)
    with pytest.raises(MathematicalDomainError, match="0 <= ciphertext < n"):
        textbook_rsa_decrypt(-1, key)


def test_educational_key_generation() -> None:
    generated = generate_educational_rsa_key(prime_bits=12, e=65_537)
    key = generated.key
    assert key.p.bit_length() == 12
    assert key.q.bit_length() == 12
    assert key.p != key.q
    assert key.n == key.p * key.q
    assert (key.e * key.d) % key.phi == 1
    assert generated.attempts >= 2
    assert generated.randomness == "Python secrets.randbits"


def test_educational_generation_validation() -> None:
    with pytest.raises(InputValidationError, match="between 4 and 20"):
        generate_educational_rsa_key(prime_bits=3)
    with pytest.raises(MathematicalDomainError, match="odd integer"):
        generate_educational_rsa_key(prime_bits=12, e=16)


def test_unsigned_big_endian_integer_byte_conversions() -> None:
    encoded = integer_to_bytes(3233)
    assert encoded.bytes_hex == "0ca1"
    assert encoded.length == 2
    assert bytes_to_integer(bytes.fromhex(encoded.bytes_hex)).integer == 3233

    zero = integer_to_bytes(0)
    assert zero.bytes_hex == "00"
    padded = integer_to_bytes(1, length=4)
    assert padded.bytes_hex == "00000001"


def test_integer_byte_conversion_validation() -> None:
    with pytest.raises(MathematicalDomainError, match="non-negative"):
        integer_to_bytes(-1)
    with pytest.raises(InputValidationError, match="at least 1"):
        integer_to_bytes(1, length=0)
    with pytest.raises(InputValidationError, match="requires at least 2"):
        integer_to_bytes(256, length=1)
    with pytest.raises(InputValidationError, match="at least one byte"):
        bytes_to_integer(b"")
