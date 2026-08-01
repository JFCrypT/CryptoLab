from __future__ import annotations

from rich.console import Console

from cryptolab.hashing.hashes import (
    HashAlgorithm,
    avalanche_effect,
    hash_bytes,
    hash_mac_profiles,
    hash_profiles,
    verify_digest,
)
from cryptolab.hashing.hkdf_sha256 import derive_hkdf_sha256
from cryptolab.hashing.hmac_sha256 import generate_hmac_sha256, verify_hmac_sha256
from cryptolab.rendering.hashing import (
    AvalancheView,
    DigestVerificationView,
    HashComparisonView,
    HashDigestView,
    HashMACComparisonView,
    HKDFView,
    HMACVerificationView,
    HMACView,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_hash_digest_and_verification_views() -> None:
    result = hash_bytes(b"abc", HashAlgorithm.SHA256, source_kind="text")
    view = HashDigestView(result)
    assert result.digest_hex in render_text(view)
    assert view.render_json(explain=True)["implementation"] == "library-backed"
    assert "operatorname" in view.render_latex(explain=True)

    verified = verify_digest(computed=result, expected_digest=bytes.fromhex(result.digest_hex))
    verify_view = DigestVerificationView(verified)
    assert "Digest valid: True" in render_text(verify_view)
    assert verify_view.render_json(explain=False)["result"]["valid"] is True
    assert "verified" in verify_view.render_latex(explain=False)


def test_avalanche_view_all_formats() -> None:
    view = AvalancheView(avalanche_effect(b"abc", b"abd", HashAlgorithm.SHA3_256))
    text = render_text(view)
    assert "Changed digest bits" in text
    assert "statistical proof" in text
    payload = view.render_json(explain=True)
    assert len(payload["trace"]) == 32
    assert "Delta" in view.render_latex(explain=True)


def test_hash_comparison_views_all_formats() -> None:
    hashes = HashComparisonView(hash_profiles())
    assert "Sponge" in render_text(hashes)
    assert len(hashes.render_json(explain=True)["result"]["algorithms"]) == 2
    assert "SHA-3" in hashes.render_latex(explain=True)

    hash_mac = HashMACComparisonView(hash_mac_profiles())
    assert "HMAC-SHA-256" in render_text(hash_mac)
    constructions = hash_mac.render_json(explain=True)["result"]["constructions"]
    assert len(constructions) == 2
    assert all("secret_key" in item for item in constructions)
    assert all("key_requirement" not in item for item in constructions)
    assert "Secret key" in hash_mac.render_latex(explain=True)


def test_hmac_views_all_formats() -> None:
    generated = generate_hmac_sha256(b"key", b"message")
    view = HMACView(generated, "text", "text")
    assert generated.tag_hex in render_text(view)
    assert view.render_json(explain=True)["result"]["tag_size_bits"] == 256
    assert "HMAC-SHA-256" in view.render_latex(explain=True)

    verified = verify_hmac_sha256(b"key", b"message", bytes.fromhex(generated.tag_hex))
    verify_view = HMACVerificationView(verified)
    assert "Tag valid: True" in render_text(verify_view)
    assert verify_view.render_json(explain=False)["result"]["valid"] is True
    assert "verified" in verify_view.render_latex(explain=False)


def test_hkdf_view_all_formats() -> None:
    result = derive_hkdf_sha256(ikm=b"shared secret", salt=b"salt", info=b"context", length=32)
    view = HKDFView(result, "text", "text", "text")
    text = render_text(view)
    assert "PRK:" in text
    assert "OKM:" in text
    assert "password-hashing" in text
    payload = view.render_json(explain=True)
    assert len(payload["trace"]) == 2
    assert payload["result"]["complete_derivation_matches"] is True
    assert "OKM" in view.render_latex(explain=True)
