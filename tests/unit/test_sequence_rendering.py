from __future__ import annotations

from rich.console import Console

from cryptolab.rendering.sequences import (
    LFSRDiagramView,
    LFSRGenerationView,
    LFSRPeriodView,
    SequenceAnalysisView,
)
from cryptolab.sequences.analysis import analyze_binary_sequence
from cryptolab.sequences.lfsr import (
    describe_lfsr,
    detect_lfsr_period,
    generate_lfsr,
    parse_feedback_polynomial,
    parse_seed,
)


def render_text(view: object, *, explain: bool = True) -> str:
    console = Console(record=True, force_terminal=False, no_color=True)
    view.render_human(console, explain=explain)  # type: ignore[attr-defined]
    return console.export_text(clear=False)


def lfsr_inputs() -> tuple[object, tuple[int, ...]]:
    polynomial = parse_feedback_polynomial("x^3+x^2+1")
    return polynomial, parse_seed("101", polynomial.degree)


def test_lfsr_generation_view_all_formats() -> None:
    polynomial, seed = lfsr_inputs()
    result = generate_lfsr(polynomial, seed, 7)  # type: ignore[arg-type]
    view = LFSRGenerationView(result)
    assert "Convention" in render_text(view)
    payload = view.render_json(explain=True)
    assert payload["result"]["output"] == "1010011"
    assert payload["trace"]
    assert "S_0" in view.render_latex(explain=True)


def test_lfsr_period_view_zero_and_nonzero() -> None:
    polynomial, seed = lfsr_inputs()
    view = LFSRPeriodView(detect_lfsr_period(polynomial, seed))  # type: ignore[arg-type]
    assert "Maximum-length sequence: True" in render_text(view)
    assert view.render_json(explain=False)["result"]["period"] == 7
    assert "T_{" in view.render_latex(explain=True)

    zero = LFSRPeriodView(detect_lfsr_period(polynomial, (0, 0, 0)))  # type: ignore[arg-type]
    assert "fixed point" in render_text(zero)


def test_lfsr_diagram_view_all_formats() -> None:
    polynomial, _ = lfsr_inputs()
    view = LFSRDiagramView(describe_lfsr(polynomial))  # type: ignore[arg-type]
    assert "feedback -> [s_2]" in render_text(view)
    assert view.render_json(explain=False)["result"]["output_stage"] == "s_0"
    assert "right" in view.render_latex(explain=True)


def test_sequence_analysis_view_all_formats() -> None:
    view = SequenceAnalysisView(analyze_binary_sequence("1010011"))
    text = render_text(view)
    assert "Fundamental period" in text
    assert "coincidences - differences" in text
    payload = view.render_json(explain=True)
    assert payload["result"]["balanced"] is True
    assert payload["result"]["autocorrelation"][1]["value"] == -1
    assert "C(" in view.render_latex(explain=True)


def test_sequence_analysis_truncation_message() -> None:
    view = SequenceAnalysisView(analyze_binary_sequence("1010011", max_lag=2))
    assert "truncated" in render_text(view, explain=False)
