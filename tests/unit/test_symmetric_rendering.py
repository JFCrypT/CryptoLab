from __future__ import annotations

from rich.console import Console

from cryptolab.rendering.symmetric import (
    BitXORView,
    ByteXORView,
    OTPRequirementsView,
    VernamView,
    XORTruthTableView,
)
from cryptolab.symmetric.otp import otp_requirements
from cryptolab.symmetric.vernam import vernam_encrypt
from cryptolab.symmetric.xor import xor_bits, xor_bytes, xor_truth_table


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def test_truth_table_view_all_formats() -> None:
    view = XORTruthTableView(xor_truth_table())
    assert "x XOR y" in render_text(view)
    assert len(view.render_json(explain=False)["result"]["rows"]) == 4
    assert "oplus" in view.render_latex(explain=False)


def test_bit_xor_view_all_formats() -> None:
    view = BitXORView(xor_bits("1011", "1111"))
    assert "XOR is self-inverse" in render_text(view)
    assert view.render_json(explain=True)["trace"]
    assert "0100" in view.render_latex(explain=True)


def test_byte_xor_view_all_formats() -> None:
    view = ByteXORView(xor_bytes(bytes.fromhex("beca"), bytes.fromhex("fe12")), "hex", "hex")
    assert "40d8" in render_text(view)
    payload = view.render_json(explain=True)
    assert payload["result"]["output_hex"] == "40d8"
    assert payload["trace"]
    assert "mathtt" in view.render_latex(explain=True)


def test_vernam_view_all_formats() -> None:
    view = VernamView(
        vernam_encrypt(bytes.fromhex("beca"), bytes.fromhex("fe12")),
        "hex",
        "hex",
    )
    assert "same XOR operation" in render_text(view)
    payload = view.render_json(explain=True)
    assert payload["command"] == "symmetric.vernam.encrypt"
    assert payload["trace"]
    assert "c_i" in view.render_latex(explain=True)


def test_otp_requirements_view_all_formats() -> None:
    view = OTPRequirementsView(otp_requirements())
    assert "cannot prove" in render_text(view)
    payload = view.render_json(explain=False)
    assert payload["result"]["cryptolab_can_verify_otp_status"] is False
    assert "uniform-random-key" in view.render_latex(explain=False)
