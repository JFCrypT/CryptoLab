from __future__ import annotations

from rich.console import Console

from cryptolab.public_key.modern_curves import (
    ed25519_private_key_from_raw,
    ed25519_public_key_from_raw,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_key_pair,
    key_agreement_profiles,
    perform_x25519_exchange,
    signature_profiles,
    x25519_private_key_from_raw,
)
from cryptolab.rendering.modern_curves import (
    CurveKeyGenerationView,
    Ed25519SignatureView,
    Ed25519VerificationView,
    KeyAgreementComparisonView,
    SignatureComparisonView,
    X25519ExchangeView,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True, width=240)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_curve_key_generation_view_all_formats() -> None:
    material = generate_ed25519_key_pair()
    view = CurveKeyGenerationView(material, "/tmp/private.pem", "/tmp/public.pem")  # noqa: S108
    text = render_text(view)
    assert "Ed25519" in text
    assert "0600" in text
    payload = view.render_json(explain=True)
    assert payload["result"]["algorithm"] == "Ed25519"
    assert "private_pem" not in payload["result"]
    assert "Ed25519 public key" in view.render_latex(explain=False)


def test_x25519_exchange_view_all_formats() -> None:
    alice = x25519_private_key_from_raw(
        bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    )
    bob = x25519_private_key_from_raw(
        bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    )
    result = perform_x25519_exchange(
        alice_private_key=alice,
        bob_private_key=bob,
        salt=None,
        info=b"",
    )
    view = X25519ExchangeView(result)
    text = render_text(view)
    assert "Shared secret matches: True" in text
    assert "does not authenticate" in text
    payload = view.render_json(explain=True)
    assert payload["result"]["shared_secret_matches"] is True
    assert "HKDF" in view.render_latex(explain=True)


def test_ed25519_views_all_formats() -> None:
    private_key = ed25519_private_key_from_raw(
        bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    )
    signed = ed25519_sign(private_key, b"")
    sign_view = Ed25519SignatureView(signed, "hex")
    sign_text = render_text(sign_view)
    assert signed.signature_hex in sign_text.replace("\n", "")
    assert "Deterministic" in sign_text
    assert sign_view.render_json(explain=True)["result"]["signature_length_bytes"] == 64
    assert "64" in sign_view.render_latex(explain=True)

    public_key = ed25519_public_key_from_raw(bytes.fromhex(signed.public_key_hex))
    verified = Ed25519VerificationView(
        ed25519_verify(public_key, b"", bytes.fromhex(signed.signature_hex))
    )
    verify_text = render_text(verified)
    assert "Signature valid: True" in verify_text
    assert "real-world identity" in verify_text
    assert verified.render_json(explain=True)["result"]["valid"] is True
    assert "true" in verified.render_latex(explain=False)


def test_comparison_views_all_formats() -> None:
    agreements = KeyAgreementComparisonView(key_agreement_profiles())
    agreement_text = render_text(agreements)
    assert "Finite-field Diffie-Hellman" in agreement_text
    assert "X25519" in agreement_text
    assert "Neither construction authenticates" in agreement_text
    assert len(agreements.render_json(explain=True)["result"]) == 2
    assert "array" in agreements.render_latex(explain=False)

    signatures = SignatureComparisonView(signature_profiles())
    signature_text = render_text(signatures)
    assert "RSA-PSS" in signature_text
    assert "Ed25519" in signature_text
    assert "HMAC-SHA-256" in signature_text
    assert "not provide technical non-repudiation" in signature_text
    assert len(signatures.render_json(explain=True)["result"]) == 3
    assert "array" in signatures.render_latex(explain=False)
