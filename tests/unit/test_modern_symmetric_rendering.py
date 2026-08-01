from __future__ import annotations

from rich.console import Console

from cryptolab.rendering.modern_symmetric import (
    AEADComparisonView,
    AESModeComparisonView,
    ModernCipherView,
)
from cryptolab.symmetric.modern import (
    AESMode,
    aead_profiles,
    aes_encrypt,
    aes_mode_profiles,
    chacha20_poly1305_encrypt,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_aes_result_view_all_formats_and_warnings() -> None:
    result = aes_encrypt(
        mode=AESMode.ECB,
        key=bytes(16),
        plaintext=bytes(16),
    )
    view = ModernCipherView(result, "hex")
    text = render_text(view)
    assert "AES-128" in text
    assert "repeated-block patterns" in text
    payload = view.render_json(explain=True)
    assert payload["implementation"] == "library-backed"
    assert payload["result"]["output_hex"] == result.output_hex
    assert "mathtt" in view.render_latex(explain=True)


def test_aead_result_view_includes_tag() -> None:
    result = chacha20_poly1305_encrypt(
        key=bytes(32),
        nonce=bytes(12),
        plaintext=b"message",
        aad=b"header",
    )
    view = ModernCipherView(result, "text; aad=text")
    text = render_text(view)
    assert "Tag:" in text
    payload = view.render_json(explain=False)
    assert payload["result"]["tag_hex"] == result.tag_hex
    assert "tag" in view.render_latex(explain=True)


def test_xts_and_unauthenticated_warnings() -> None:
    xts = aes_encrypt(
        mode=AESMode.XTS,
        key=b"a" * 16 + b"b" * 16,
        plaintext=bytes(16),
        tweak=bytes(16),
    )
    assert "storage data units" in render_text(ModernCipherView(xts, "hex"))

    ctr = aes_encrypt(
        mode=AESMode.CTR,
        key=bytes(16),
        plaintext=b"abc",
        counter=bytes(16),
    )
    assert "no authentication" in render_text(ModernCipherView(ctr, "text"))


def test_mode_comparison_view_all_formats() -> None:
    view = AESModeComparisonView(aes_mode_profiles())
    text = render_text(view)
    assert "CFB-128" in text
    assert "universally superior" in text
    payload = view.render_json(explain=True)
    assert len(payload["result"]["modes"]) == 7
    assert "array" in view.render_latex(explain=True)


def test_aead_comparison_view_all_formats() -> None:
    view = AEADComparisonView(aead_profiles())
    text = render_text(view)
    assert "AES-GCM" in text
    assert "ChaCha20-Poly1305" in text
    payload = view.render_json(explain=True)
    assert len(payload["result"]["constructions"]) == 2
    assert "Nonce" in view.render_latex(explain=True)
