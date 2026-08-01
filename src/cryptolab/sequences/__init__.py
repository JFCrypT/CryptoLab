"""Educational pseudorandom-sequence generation and analysis."""

from cryptolab.sequences.analysis import (
    AutocorrelationValue,
    RunCount,
    SequenceAnalysisResult,
    analyze_binary_sequence,
)
from cryptolab.sequences.lfsr import (
    FeedbackPolynomial,
    LFSRDiagramResult,
    LFSRGenerationResult,
    LFSRPeriodResult,
    LFSRTransition,
    describe_lfsr,
    detect_lfsr_period,
    generate_lfsr,
    parse_feedback_polynomial,
    parse_seed,
)

__all__ = [
    "AutocorrelationValue",
    "FeedbackPolynomial",
    "LFSRDiagramResult",
    "LFSRGenerationResult",
    "LFSRPeriodResult",
    "LFSRTransition",
    "RunCount",
    "SequenceAnalysisResult",
    "analyze_binary_sequence",
    "describe_lfsr",
    "detect_lfsr_period",
    "generate_lfsr",
    "parse_feedback_polynomial",
    "parse_seed",
]
