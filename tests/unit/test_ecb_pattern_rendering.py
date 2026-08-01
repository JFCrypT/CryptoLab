from __future__ import annotations

from rich.console import Console

from cryptolab.labs.ecb_pattern_leakage import run_ecb_pattern_leakage_lab
from cryptolab.rendering.labs import ECBPatternLeakageLabView


def render_text(view: ECBPatternLeakageLabView, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)
    return console.export_text(clear=False)


def test_ecb_pattern_view_all_formats() -> None:
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    view = ECBPatternLeakageLabView(
        run_ecb_pattern_leakage_lab(key=bytes(16), plaintext=block + bytes(16) + block)
    )
    text = render_text(view)
    assert "Repeated pattern preserved: True" in text
    assert "Mitigation" in text
    payload = view.render_json(explain=True)
    assert payload["result"]["repeated_pattern_preserved"] is True
    assert len(payload["result"]["blocks"]) == 3
    assert "Longrightarrow" in view.render_latex(explain=True)
