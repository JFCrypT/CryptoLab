from __future__ import annotations

from rich.console import Console

from cryptolab.public_key.rsa_applied import (
    generate_rsa_key_pair,
    load_rsa_private_key,
    load_rsa_public_key,
    rsa_oaep_encrypt,
    rsa_profiles,
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
from cryptolab.rendering.rsa import (
    EducationalRSADecryptionView,
    EducationalRSAKeyView,
    EducationalRSAOperationView,
    IntegerBytesView,
    RSAComparisonView,
    RSAKeyGenerationView,
    RSAOAEPView,
    RSAPSSVerificationView,
    RSAPSSView,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_educational_rsa_views_all_formats() -> None:
    key = build_educational_rsa_key(61, 53, 17)
    key_view = EducationalRSAKeyView(key)
    assert "lambda(n)" in render_text(key_view)
    assert key_view.render_json(explain=True)["result"]["d"] == 2753
    assert key_view.render_json(explain=True)["result"]["d_carmichael"] == 413
    assert "varphi" in key_view.render_latex(explain=True)

    encrypted = EducationalRSAOperationView(textbook_rsa_encrypt(65, key))
    assert "2790" in render_text(encrypted)
    assert encrypted.render_json(explain=True)["trace"]
    assert "bmod" in encrypted.render_latex(explain=True)

    decrypted = EducationalRSADecryptionView(textbook_rsa_decrypt(2790, key))
    assert "CRT matches standard" in render_text(decrypted)
    assert decrypted.render_json(explain=True)["result"]["plaintext"] == 65
    assert "m_1" in decrypted.render_latex(explain=True)


def test_integer_bytes_view_all_formats() -> None:
    encoded = IntegerBytesView(integer_to_bytes(3233))
    assert render_text(encoded, explain=False).strip() == "0ca1"
    assert encoded.render_json(explain=True)["result"]["integer"] == 3233
    assert "longleftrightarrow" in encoded.render_latex(explain=True)
    decoded = IntegerBytesView(bytes_to_integer(bytes.fromhex("0ca1")))
    assert render_text(decoded, explain=False).strip() == "3233"


def test_applied_rsa_views_all_formats() -> None:
    material = generate_rsa_key_pair(key_size=2048)
    private_key = load_rsa_private_key(material.private_pem)
    public_key = load_rsa_public_key(material.public_pem)

    key_view = RSAKeyGenerationView(material, "private.pem", "public.pem")
    assert "Public fingerprint" in render_text(key_view)
    assert key_view.render_json(explain=True)["result"]["private_key_path"] == "private.pem"
    assert "SHA256" in key_view.render_latex(explain=True)

    encrypted = rsa_oaep_encrypt(public_key, b"message")
    oaep_view = RSAOAEPView(encrypted, "text")
    assert "Maximum plaintext" in render_text(oaep_view)
    assert oaep_view.render_json(explain=True)["result"]["randomized"]
    assert "RSA" in oaep_view.render_latex(explain=True)

    signed = rsa_pss_sign(private_key, b"message")
    pss_view = RSAPSSView(signed, "text")
    assert "Salt length" in render_text(pss_view)
    assert pss_view.render_json(explain=True)["result"]["randomized"]
    assert "sigma" in pss_view.render_latex(explain=True)

    verified = rsa_pss_verify(public_key, b"message", bytes.fromhex(signed.signature_hex))
    verify_view = RSAPSSVerificationView(verified)
    assert "Signature valid: True" in render_text(verify_view)
    assert verify_view.render_json(explain=False)["result"]["valid"]
    assert "Verify" in verify_view.render_latex(explain=True)


def test_rsa_comparison_view_all_formats() -> None:
    view = RSAComparisonView(rsa_profiles())
    text = render_text(view)
    assert "Textbook RSA" in text
    assert "Hybrid encryption" in text
    payload = view.render_json(explain=True)
    assert len(payload["result"]["constructions"]) == 3
    assert "array" in view.render_latex(explain=True)
