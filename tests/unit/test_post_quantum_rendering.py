from __future__ import annotations

from io import StringIO

from rich.console import Console

from cryptolab.post_quantum.comparisons import post_quantum_key_establishment_profiles
from cryptolab.post_quantum.foundations import negacyclic_multiply, toy_lwe_sample
from cryptolab.post_quantum.ml_dsa import (
    MLDSASignatureResult,
    MLDSAVerificationResult,
    ml_dsa_parameter_profiles,
)
from cryptolab.post_quantum.ml_kem import (
    MLKEMDecapsulationResult,
    MLKEMEncapsulationResult,
    ml_kem_parameter_profiles,
)
from cryptolab.post_quantum.openssl_backend import OpenSSLKeyPairMaterial, OpenSSLPQCStatus
from cryptolab.post_quantum.slh_dsa import (
    SLHDSASignatureResult,
    SLHDSAVerificationResult,
    slh_dsa_parameter_profiles,
)
from cryptolab.rendering.post_quantum import (
    MLDSAParametersView,
    MLKEMDecapsulationView,
    MLKEMEncapsulationView,
    MLKEMParametersView,
    NegacyclicMultiplicationView,
    OpenSSLPQCStatusView,
    PQCComparisonView,
    PQCKeyGenerationView,
    PQCSignatureView,
    PQCVerificationView,
    SLHDSAParametersView,
    ToyLWEView,
)


def render_text(view: object, *, explain: bool = True) -> str:
    stream = StringIO()
    console = Console(file=stream, force_terminal=False, no_color=True, width=180)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return stream.getvalue()


def test_backend_foundation_and_parameter_views_all_formats() -> None:
    status = OpenSSLPQCStatus(
        executable="/usr/bin/openssl",
        version_text="OpenSSL 3.5.5",
        version=(3, 5, 5),
        minimum_version="3.5.0",
        ml_kem=("ML-KEM-512",),
        ml_dsa=("ML-DSA-44",),
        slh_dsa=(),
        ready=False,
    )
    status_view = OpenSSLPQCStatusView(status)
    assert "PQC backend ready" in render_text(status_view)
    assert status_view.render_json(explain=True)["result"]["ready"] is False
    assert "false" in status_view.render_latex(explain=False)

    ring_view = NegacyclicMultiplicationView(negacyclic_multiply((1, 2), (3, 4), modulus=17))
    assert "Z_17" in render_text(ring_view)
    assert ring_view.render_json(explain=True)["trace"]
    assert "bmod" in ring_view.render_latex(explain=True)

    lwe_view = ToyLWEView(toy_lwe_sample(((1, 2),), (3, 4), (1,), modulus=17))
    assert "A*s + e" in render_text(lwe_view)
    assert lwe_view.render_json(explain=True)["result"]["b"]
    assert "As+e" in lwe_view.render_latex(explain=True)

    for view, expected in (
        (MLKEMParametersView(ml_kem_parameter_profiles()), "ML-KEM-768"),
        (MLDSAParametersView(ml_dsa_parameter_profiles()), "ML-DSA-65"),
        (SLHDSAParametersView(slh_dsa_parameter_profiles()), "SLH-DSA-SHAKE-256f"),
    ):
        assert expected in render_text(view)
        assert view.render_json(explain=True)["result"]
        assert "text" in view.render_latex(explain=False)


def test_key_kem_signature_and_comparison_views() -> None:
    material = OpenSSLKeyPairMaterial(
        algorithm="ML-KEM-768",
        standard="FIPS 203",
        private_pem=b"private",
        public_pem=b"public",
        public_fingerprint_sha256="a" * 64,
        private_format="PKCS#8 PEM (unencrypted)",
        public_format="SubjectPublicKeyInfo PEM",
        private_encrypted=False,
        library="OpenSSL 3.5.5 EVP",
    )
    key_view = PQCKeyGenerationView(material, "private.pem", "public.pem")
    assert "ML-KEM-768" in render_text(key_view)
    assert key_view.render_json(explain=True)["implementation"] == "library-backed"
    assert "SHA256" in key_view.render_latex(explain=False)

    enc = MLKEMEncapsulationResult(
        parameter_set="ML-KEM-768",
        ciphertext_hex="aa",
        shared_secret_hex="bb",  # noqa: S106
        ciphertext_length_bytes=1088,
        shared_secret_length_bytes=32,
        standard="FIPS 203",
        library="OpenSSL 3.5.5 EVP",
    )
    enc_view = MLKEMEncapsulationView(enc, "ct.bin", "secret.bin")
    assert "Ciphertext" in render_text(enc_view)
    assert enc_view.render_json(explain=True)["result"]["shared_secret_hex"] == "bb"  # noqa: S105
    assert "1088" in enc_view.render_latex(explain=True)

    dec = MLKEMDecapsulationResult(
        parameter_set="ML-KEM-768",
        ciphertext_hex="aa",
        shared_secret_hex="bb",  # noqa: S106
        ciphertext_length_bytes=1088,
        shared_secret_length_bytes=32,
        standard="FIPS 203",
        library="OpenSSL 3.5.5 EVP",
    )
    dec_view = MLKEMDecapsulationView(dec, "secret.bin")
    assert "Shared secret" in render_text(dec_view)
    assert dec_view.render_json(explain=True)["result"]["parameter_set"] == "ML-KEM-768"
    assert "32" in dec_view.render_latex(explain=False)

    ml_sig = MLDSASignatureResult(
        parameter_set="ML-DSA-44",
        message_hex="41",
        context_hex="",
        signature_hex="ab",
        signature_length_bytes=2420,
        public_fingerprint_sha256="b" * 64,
        hedged_signing=True,
        standard="FIPS 204",
        library="OpenSSL 3.5.5 EVP",
    )
    sig_view = PQCSignatureView(ml_sig, "text", "signature.bin")
    assert "2420" in render_text(sig_view)
    assert sig_view.render_json(explain=True)["inputs"]["message_source"] == "text"
    assert "2420" in sig_view.render_latex(explain=True)

    slh_sig = SLHDSASignatureResult(
        parameter_set="SLH-DSA-SHAKE-128s",
        message_hex="41",
        context_hex="01",
        signature_hex="cd",
        signature_length_bytes=7856,
        public_fingerprint_sha256="c" * 64,
        standard="FIPS 205",
        library="OpenSSL 3.5.5 EVP",
    )
    assert "7856" in render_text(PQCSignatureView(slh_sig, "hex", None))

    for result in (
        MLDSAVerificationResult("ML-DSA-44", "41", "", "ab", True, "FIPS 204", "OpenSSL"),
        SLHDSAVerificationResult(
            "SLH-DSA-SHAKE-128s", "41", "", "cd", False, "FIPS 205", "OpenSSL"
        ),
    ):
        verify_view = PQCVerificationView(result)
        assert "Signature valid" in render_text(verify_view)
        assert verify_view.render_json(explain=True)["result"]["valid"] is result.valid
        assert "Verify" in verify_view.render_latex(explain=False)

    comparison = PQCComparisonView(
        "post-quantum.compare-key-establishment",
        post_quantum_key_establishment_profiles(),
    )
    assert "ML-KEM" in render_text(comparison)
    assert len(comparison.render_json(explain=True)["result"]) == 3
    assert "X25519" in comparison.render_latex(explain=False)
