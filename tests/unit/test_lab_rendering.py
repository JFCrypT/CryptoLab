from __future__ import annotations

from rich.console import Console

from cryptolab.classical.alphabet import load_builtin_alphabet
from cryptolab.labs.caesar_brute_force import run_caesar_brute_force_lab
from cryptolab.labs.models import APPROVED_LABS
from cryptolab.labs.vernam_key_reuse import run_vernam_key_reuse_lab
from cryptolab.rendering.labs import (
    CaesarBruteForceLabView,
    LabListView,
    VernamKeyReuseLabView,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_lab_list_view_all_formats() -> None:
    view = LabListView(APPROVED_LABS)
    assert "caesar-brute-force" in render_text(view)
    assert len(view.render_json(explain=False)["result"]["laboratories"]) == 4
    assert "begin" in view.render_latex(explain=False)


def test_caesar_lab_view_all_formats() -> None:
    result = run_caesar_brute_force_lab("KHOOR", load_builtin_alphabet("latin-upper"))
    view = CaesarBruteForceLabView(result)
    assert "HELLO" in render_text(view)
    assert view.render_json(explain=True)["result"]["key_space_size"] == 26
    assert "candidate" in view.render_latex(explain=True)


def test_vernam_reuse_view_all_formats() -> None:
    result = run_vernam_key_reuse_lab(
        bytes.fromhex("beca"),
        bytes.fromhex("bcee"),
        bytes.fromhex("fe12"),
    )
    view = VernamKeyReuseLabView(result)
    assert "Identity holds: True" in render_text(view)
    assert view.render_json(explain=True)["result"]["identity_holds"] is True
    assert "C_1" in view.render_latex(explain=True)
