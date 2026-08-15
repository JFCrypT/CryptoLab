from __future__ import annotations

from dataclasses import replace

import pytest

from cryptolab.exceptions import InputValidationError
from cryptolab.post_quantum import ml_dsa as ml_dsa_module
from cryptolab.post_quantum import ml_kem as ml_kem_module
from cryptolab.post_quantum import slh_dsa as slh_dsa_module
from cryptolab.post_quantum.comparisons import (
    classical_post_quantum_profiles,
    post_quantum_key_establishment_profiles,
    post_quantum_signature_profiles,
)
from cryptolab.post_quantum.ml_dsa import MLDSAParameterSet
from cryptolab.post_quantum.ml_kem import MLKEMParameterSet
from cryptolab.post_quantum.openssl_backend import OpenSSLKeyPairMaterial
from cryptolab.post_quantum.slh_dsa import SLHDSAParameterSet

KEY_PAIR = OpenSSLKeyPairMaterial(
    algorithm="test",
    standard="FIPS",
    private_pem=b"private",
    public_pem=b"public",
    public_fingerprint_sha256="a" * 64,
    private_format="PKCS#8 PEM (unencrypted)",
    public_format="SubjectPublicKeyInfo PEM",
    private_encrypted=False,
    library="OpenSSL 3.5 EVP",
)


def test_standardized_parameter_profiles_have_expected_scope() -> None:
    kem = ml_kem_module.ml_kem_parameter_profiles()
    dsa = ml_dsa_module.ml_dsa_parameter_profiles()
    slh = slh_dsa_module.slh_dsa_parameter_profiles()
    assert [profile.parameter_set for profile in kem] == [
        value.value for value in MLKEMParameterSet
    ]
    assert [profile.parameter_set for profile in dsa] == [
        value.value for value in MLDSAParameterSet
    ]
    assert [profile.parameter_set for profile in slh] == [
        value.value for value in SLHDSAParameterSet
    ]
    assert [profile.ciphertext_bytes for profile in kem] == [768, 1088, 1568]
    assert [profile.signature_bytes for profile in dsa] == [2420, 3309, 4627]
    assert len(slh) == 12
    assert slh[0].signature_bytes == 7856
    assert slh[-1].signature_bytes == 49856


def test_profile_accessors_and_comparisons() -> None:
    assert ml_kem_module.ml_kem_profile(MLKEMParameterSet.ML_KEM_768).security_category == 3
    assert ml_dsa_module.ml_dsa_profile(MLDSAParameterSet.ML_DSA_65).security_category == 3
    assert slh_dsa_module.slh_dsa_profile(SLHDSAParameterSet.SHAKE_256F).hash_family == "SHAKE"
    assert [row.construction for row in post_quantum_key_establishment_profiles()] == [
        "Finite-field Diffie-Hellman",
        "X25519",
        "ML-KEM",
    ]
    assert [row.construction for row in post_quantum_signature_profiles()] == [
        "RSA-PSS",
        "Ed25519",
        "ML-DSA",
        "SLH-DSA",
    ]
    assert len(classical_post_quantum_profiles()) == 6


def test_key_generation_delegates_to_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, str]] = []

    def fake_generate(algorithm: str, *, standard: str, kind: str) -> OpenSSLKeyPairMaterial:
        calls.append((algorithm, standard, kind))
        return replace(KEY_PAIR, algorithm=algorithm, standard=standard)

    monkeypatch.setattr(ml_kem_module, "generate_key_pair", fake_generate)
    monkeypatch.setattr(ml_dsa_module, "generate_key_pair", fake_generate)
    monkeypatch.setattr(slh_dsa_module, "generate_key_pair", fake_generate)
    assert (
        ml_kem_module.generate_ml_kem_key_pair(MLKEMParameterSet.ML_KEM_512).algorithm
        == "ML-KEM-512"
    )
    assert (
        ml_dsa_module.generate_ml_dsa_key_pair(MLDSAParameterSet.ML_DSA_44).algorithm == "ML-DSA-44"
    )
    assert (
        slh_dsa_module.generate_slh_dsa_key_pair(SLHDSAParameterSet.SHA2_128S).algorithm
        == "SLH-DSA-SHA2-128s"
    )
    assert calls == [
        ("ML-KEM-512", "FIPS 203", "kem"),
        ("ML-DSA-44", "FIPS 204", "signature-ml-dsa"),
        ("SLH-DSA-SHA2-128s", "FIPS 205", "signature-slh-dsa"),
    ]


def test_ml_kem_round_trip_wrappers_and_size_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = ml_kem_module.ml_kem_profile(MLKEMParameterSet.ML_KEM_512)
    ciphertext = b"c" * profile.ciphertext_bytes
    secret = b"s" * profile.shared_secret_bytes
    monkeypatch.setattr(
        ml_kem_module,
        "kem_encapsulate",
        lambda algorithm, public_pem: (ciphertext, secret, "OpenSSL 3.5 EVP"),
    )
    monkeypatch.setattr(
        ml_kem_module,
        "kem_decapsulate",
        lambda algorithm, private_pem, supplied: (secret, "OpenSSL 3.5 EVP"),
    )
    encapsulated = ml_kem_module.ml_kem_encapsulate(MLKEMParameterSet.ML_KEM_512, b"public")
    assert encapsulated.ciphertext_length_bytes == profile.ciphertext_bytes
    assert encapsulated.shared_secret_hex == secret.hex()
    decapsulated = ml_kem_module.ml_kem_decapsulate(
        MLKEMParameterSet.ML_KEM_512, b"private", ciphertext
    )
    assert decapsulated.shared_secret_hex == secret.hex()
    with pytest.raises(InputValidationError, match="exactly"):
        ml_kem_module.ml_kem_decapsulate(MLKEMParameterSet.ML_KEM_512, b"private", b"short")

    monkeypatch.setattr(
        ml_kem_module,
        "kem_encapsulate",
        lambda algorithm, public_pem: (b"short", secret, "OpenSSL"),
    )
    with pytest.raises(InputValidationError, match="ciphertext bytes"):
        ml_kem_module.ml_kem_encapsulate(MLKEMParameterSet.ML_KEM_512, b"public")
    monkeypatch.setattr(
        ml_kem_module,
        "kem_encapsulate",
        lambda algorithm, public_pem: (ciphertext, b"short", "OpenSSL"),
    )
    with pytest.raises(InputValidationError, match="shared-secret bytes"):
        ml_kem_module.ml_kem_encapsulate(MLKEMParameterSet.ML_KEM_512, b"public")
    monkeypatch.setattr(
        ml_kem_module,
        "kem_decapsulate",
        lambda algorithm, private_pem, supplied: (b"short", "OpenSSL"),
    )
    with pytest.raises(InputValidationError, match="unexpected shared-secret"):
        ml_kem_module.ml_kem_decapsulate(MLKEMParameterSet.ML_KEM_512, b"private", ciphertext)


def test_signature_wrappers_and_length_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    message = b"CryptoLab"
    context = b"context"
    ml_profile = ml_dsa_module.ml_dsa_profile(MLDSAParameterSet.ML_DSA_44)
    ml_sig = b"m" * ml_profile.signature_bytes
    monkeypatch.setattr(
        ml_dsa_module,
        "sign_message",
        lambda *args, **kwargs: (ml_sig, "f" * 64, "OpenSSL 3.5 EVP"),
    )
    monkeypatch.setattr(
        ml_dsa_module,
        "verify_message",
        lambda *args, **kwargs: (True, "OpenSSL 3.5 EVP"),
    )
    signed = ml_dsa_module.ml_dsa_sign(
        MLDSAParameterSet.ML_DSA_44, b"private", message, context=context
    )
    assert signed.signature_length_bytes == ml_profile.signature_bytes
    assert signed.hedged_signing
    assert ml_dsa_module.ml_dsa_verify(
        MLDSAParameterSet.ML_DSA_44, b"public", message, ml_sig, context=context
    ).valid
    assert not ml_dsa_module.ml_dsa_verify(
        MLDSAParameterSet.ML_DSA_44, b"public", message, b"short", context=context
    ).valid
    monkeypatch.setattr(
        ml_dsa_module,
        "sign_message",
        lambda *args, **kwargs: (b"short", "f" * 64, "OpenSSL"),
    )
    with pytest.raises(InputValidationError, match="signature bytes"):
        ml_dsa_module.ml_dsa_sign(MLDSAParameterSet.ML_DSA_44, b"private", message)

    slh_profile = slh_dsa_module.slh_dsa_profile(SLHDSAParameterSet.SHAKE_128S)
    slh_sig = b"s" * slh_profile.signature_bytes
    monkeypatch.setattr(
        slh_dsa_module,
        "sign_message",
        lambda *args, **kwargs: (slh_sig, "e" * 64, "OpenSSL 3.5 EVP"),
    )
    monkeypatch.setattr(
        slh_dsa_module,
        "verify_message",
        lambda *args, **kwargs: (False, "OpenSSL 3.5 EVP"),
    )
    assert (
        slh_dsa_module.slh_dsa_sign(
            SLHDSAParameterSet.SHAKE_128S, b"private", message, context=context
        ).signature_length_bytes
        == slh_profile.signature_bytes
    )
    assert not slh_dsa_module.slh_dsa_verify(
        SLHDSAParameterSet.SHAKE_128S, b"public", message, slh_sig, context=context
    ).valid
    assert not slh_dsa_module.slh_dsa_verify(
        SLHDSAParameterSet.SHAKE_128S, b"public", message, b"short", context=context
    ).valid
    monkeypatch.setattr(
        slh_dsa_module,
        "sign_message",
        lambda *args, **kwargs: (b"short", "e" * 64, "OpenSSL"),
    )
    with pytest.raises(InputValidationError, match="signature bytes"):
        slh_dsa_module.slh_dsa_sign(SLHDSAParameterSet.SHAKE_128S, b"private", message)
