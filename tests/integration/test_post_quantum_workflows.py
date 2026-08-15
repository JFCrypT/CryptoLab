from __future__ import annotations

import pytest

from cryptolab.exceptions import InputValidationError
from cryptolab.post_quantum.ml_dsa import (
    MLDSAParameterSet,
    generate_ml_dsa_key_pair,
    ml_dsa_sign,
    ml_dsa_verify,
)
from cryptolab.post_quantum.ml_kem import (
    MLKEMParameterSet,
    generate_ml_kem_key_pair,
    ml_kem_decapsulate,
    ml_kem_encapsulate,
)
from cryptolab.post_quantum.openssl_backend import openssl_pqc_status
from cryptolab.post_quantum.slh_dsa import (
    SLHDSAParameterSet,
    generate_slh_dsa_key_pair,
    slh_dsa_sign,
    slh_dsa_verify,
)


def _backend_ready() -> bool:
    try:
        return openssl_pqc_status().ready
    except InputValidationError:
        return False


pytestmark = pytest.mark.skipif(
    not _backend_ready(),
    reason="OpenSSL 3.5+ with the complete standardized PQC algorithm set is unavailable",
)


def test_ml_kem_768_generated_round_trip() -> None:
    material = generate_ml_kem_key_pair(MLKEMParameterSet.ML_KEM_768)
    encapsulated = ml_kem_encapsulate(MLKEMParameterSet.ML_KEM_768, material.public_pem)
    decapsulated = ml_kem_decapsulate(
        MLKEMParameterSet.ML_KEM_768,
        material.private_pem,
        bytes.fromhex(encapsulated.ciphertext_hex),
    )
    assert decapsulated.shared_secret_hex == encapsulated.shared_secret_hex
    assert encapsulated.ciphertext_length_bytes == 1088
    assert encapsulated.shared_secret_length_bytes == 32


def test_ml_dsa_65_generated_sign_verify_and_reject_changed_message() -> None:
    material = generate_ml_dsa_key_pair(MLDSAParameterSet.ML_DSA_65)
    message = b"CryptoLab ML-DSA integration"
    signature = ml_dsa_sign(
        MLDSAParameterSet.ML_DSA_65,
        material.private_pem,
        message,
        context=b"cryptolab",
    )
    signature_bytes = bytes.fromhex(signature.signature_hex)
    assert signature.signature_length_bytes == 3309
    assert ml_dsa_verify(
        MLDSAParameterSet.ML_DSA_65,
        material.public_pem,
        message,
        signature_bytes,
        context=b"cryptolab",
    ).valid
    assert not ml_dsa_verify(
        MLDSAParameterSet.ML_DSA_65,
        material.public_pem,
        message + b" changed",
        signature_bytes,
        context=b"cryptolab",
    ).valid


def test_slh_dsa_shake_128s_generated_sign_verify() -> None:
    parameter_set = SLHDSAParameterSet.SHAKE_128S
    material = generate_slh_dsa_key_pair(parameter_set)
    message = b"CryptoLab SLH-DSA integration"
    signature = slh_dsa_sign(parameter_set, material.private_pem, message, context=b"cryptolab")
    assert signature.signature_length_bytes == 7856
    assert slh_dsa_verify(
        parameter_set,
        material.public_pem,
        message,
        bytes.fromhex(signature.signature_hex),
        context=b"cryptolab",
    ).valid
