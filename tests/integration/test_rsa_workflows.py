from __future__ import annotations

from cryptolab.public_key.rsa_applied import (
    generate_rsa_key_pair,
    load_rsa_private_key,
    load_rsa_public_key,
    rsa_oaep_decrypt,
    rsa_oaep_encrypt,
    rsa_pss_sign,
    rsa_pss_verify,
)
from cryptolab.public_key.rsa_educational import (
    build_educational_rsa_key,
    bytes_to_integer,
    integer_to_bytes,
    textbook_rsa_decrypt,
    textbook_rsa_encrypt,
)


def test_educational_rsa_integer_and_byte_workflow() -> None:
    key = build_educational_rsa_key(61, 53, 17)
    message = bytes_to_integer(b"A").integer
    ciphertext = textbook_rsa_encrypt(message, key).output_value
    recovered = textbook_rsa_decrypt(ciphertext, key).plaintext
    assert integer_to_bytes(recovered).bytes_hex == b"A".hex()


def test_applied_rsa_encryption_signature_and_serialization_workflow() -> None:
    material = generate_rsa_key_pair(key_size=2048)
    private_key = load_rsa_private_key(material.private_pem)
    public_key = load_rsa_public_key(material.public_pem)
    message = b"CryptoLab applied RSA workflow"

    encrypted = rsa_oaep_encrypt(public_key, message)
    decrypted = rsa_oaep_decrypt(private_key, bytes.fromhex(encrypted.output_hex))
    assert bytes.fromhex(decrypted.output_hex) == message

    signed = rsa_pss_sign(private_key, message)
    assert rsa_pss_verify(public_key, message, bytes.fromhex(signed.signature_hex)).valid
