from __future__ import annotations

from rich.console import Console

from cryptolab.labs.dh_man_in_the_middle import run_dh_man_in_the_middle_lab
from cryptolab.rendering.labs import DHManInTheMiddleLabView


def render_text(view: DHManInTheMiddleLabView, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)
    return console.export_text(clear=False)


def test_dh_mitm_view_all_formats() -> None:
    view = DHManInTheMiddleLabView(
        run_dh_man_in_the_middle_lab(
            prime=17,
            generator=3,
            alice_private=13,
            bob_private=11,
            mallory_alice_private=5,
            mallory_bob_private=7,
        )
    )
    text = render_text(view)
    assert "Mallory matches Alice: True" in text
    assert "Alice and Bob now have different secrets: True" in text
    assert "Mitigation" in text
    payload = view.render_json(explain=True)
    assert payload["result"]["alice_channel_matches"] is True
    assert payload["result"]["bob_channel_matches"] is True
    assert "K_{A,M}" in view.render_latex(explain=True)
