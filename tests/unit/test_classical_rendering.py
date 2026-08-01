from __future__ import annotations

from rich.console import Console

from cryptolab.classical.alphabet import load_builtin_alphabet
from cryptolab.classical.caesar import (
    caesar_candidates,
    caesar_encrypt,
    caesar_frequency,
    caesar_table,
)
from cryptolab.classical.polybius import build_polybius_grid, polybius_encrypt
from cryptolab.classical.vigenere import vigenere_encrypt
from cryptolab.rendering.classical import (
    CaesarCandidatesView,
    CaesarTableView,
    CaesarView,
    FrequencyView,
    PolybiusGridView,
    PolybiusView,
    VigenereAlignmentView,
    VigenereView,
)

LATIN = load_builtin_alphabet("latin-upper")


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_caesar_view_all_formats() -> None:
    view = CaesarView(caesar_encrypt("ABC", 3, LATIN))
    assert "DEF" in render_text(view)
    assert view.render_json(explain=True)["trace"]
    assert "pmod" in view.render_latex(explain=True)


def test_caesar_table_and_candidates_views() -> None:
    table = CaesarTableView(3, LATIN.name, caesar_table(3, LATIN))
    assert "Output index" in render_text(table)
    assert len(table.render_json(explain=False)["result"]["entries"]) == 26
    assert "begin" in table.render_latex(explain=False)

    candidates = CaesarCandidatesView("KHOOR", LATIN.name, caesar_candidates("KHOOR", LATIN))
    assert "HELLO" in render_text(candidates)
    assert len(candidates.render_json(explain=True)["result"]["candidates"]) == 26
    assert "Candidate" in candidates.render_latex(explain=False)


def test_frequency_view_all_formats() -> None:
    view = FrequencyView(caesar_frequency("ABRACADABRA", LATIN))
    assert "Most frequent" in render_text(view)
    assert view.render_json(explain=True)["result"]["most_frequent"] == ["A"]
    assert "Percentage" not in view.render_latex(explain=False)


def test_vigenere_view_all_formats() -> None:
    view = VigenereView(vigenere_encrypt("ATTACKATDAWN", "LEMON", LATIN))
    assert "LXFOPVEFRNHR" in render_text(view)
    assert view.render_json(explain=True)["trace"]
    assert "Repeated key" in view.render_latex(explain=True)


def test_polybius_views_all_formats() -> None:
    grid = PolybiusGridView(build_polybius_grid(LATIN))
    assert "Row\\Col" in render_text(grid)
    assert grid.render_json(explain=True)["result"]["rows"] == 6
    assert "begin" in grid.render_latex(explain=False)

    cipher = PolybiusView(polybius_encrypt("ABC D", LATIN))
    assert "u+20" in render_text(cipher)
    assert cipher.render_json(explain=True)["trace"]
    assert "Grid" in cipher.render_latex(explain=True)


def test_vigenere_alignment_view_all_formats() -> None:
    view = VigenereAlignmentView(vigenere_encrypt("A A", "BC", LATIN))
    assert "Repeated key: BC" in render_text(view)
    payload = view.render_json(explain=True)
    assert payload["command"] == "classical.vigenere.align"
    assert payload["result"]["repeated_key_alignment"][1]["key_position"] is None
    assert "begin" in view.render_latex(explain=False)
