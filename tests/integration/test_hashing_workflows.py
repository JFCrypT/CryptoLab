from __future__ import annotations

from pathlib import Path

from cryptolab.hashing.hashes import HashAlgorithm, hash_file, verify_digest
from cryptolab.hashing.hkdf_sha256 import derive_hkdf_sha256
from cryptolab.hashing.hmac_sha256 import generate_hmac_sha256, verify_hmac_sha256
from cryptolab.symmetric.modern import AESMode, aes_decrypt, aes_encrypt


def test_file_hash_and_digest_verification_workflow(tmp_path: Path) -> None:
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"CryptoLab reproducible artifact\n")
    digest = hash_file(path, HashAlgorithm.SHA256)
    verification = verify_digest(computed=digest, expected_digest=bytes.fromhex(digest.digest_hex))
    assert verification.valid


def test_hmac_generation_and_verification_workflow() -> None:
    generated = generate_hmac_sha256(b"shared key", b"authenticated message")
    verified = verify_hmac_sha256(
        b"shared key", b"authenticated message", bytes.fromhex(generated.tag_hex)
    )
    assert verified.valid


def test_hkdf_output_can_supply_aes256_key() -> None:
    derived = derive_hkdf_sha256(
        ikm=b"educational shared secret",
        salt=b"CryptoLab salt",
        info=b"CryptoLab AES-256 key",
        length=32,
    )
    key = bytes.fromhex(derived.okm_hex)
    plaintext = b"library-backed composition"
    encrypted = aes_encrypt(
        mode=AESMode.GCM,
        key=key,
        plaintext=plaintext,
        nonce=bytes(12),
        aad=b"context",
    )
    decrypted = aes_decrypt(
        mode=AESMode.GCM,
        key=key,
        ciphertext=bytes.fromhex(encrypted.output_hex),
        nonce=bytes(12),
        aad=b"context",
        tag=bytes.fromhex(encrypted.tag_hex or ""),
    )
    assert bytes.fromhex(decrypted.output_hex) == plaintext
