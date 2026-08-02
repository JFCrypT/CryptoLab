from __future__ import annotations

from rich.console import Console

from cryptolab.public_key.diffie_hellman import inspect_dh_group, perform_dh_exchange
from cryptolab.rendering.diffie_hellman import DHExchangeView, DHGroupView


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_dh_group_view_all_formats() -> None:
    view = DHGroupView(inspect_dh_group(17, 3))
    text = render_text(view)
    assert "Generator" in text
    assert "discrete logarithm" in text
    payload = view.render_json(explain=True)
    assert payload["result"]["is_generator"] is True
    assert payload["result"]["generator_checks"]
    assert "operatorname" in view.render_latex(explain=True)


def test_dh_exchange_view_all_formats() -> None:
    view = DHExchangeView(
        perform_dh_exchange(
            prime=17,
            generator=3,
            alice_private=13,
            bob_private=11,
        )
    )
    text = render_text(view)
    assert "Shared secret matches: True" in text
    assert "HKDF-SHA-256 session key" in text
    assert "key agreement, not encryption" in text
    payload = view.render_json(explain=True)
    assert payload["result"]["alice_shared_secret"] == 6
    assert len(payload["trace"]) == 4
    assert "HKDF" in view.render_latex(explain=True)
