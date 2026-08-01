"""Elementary analysis of finite binary sequences."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.encoding import validate_bit_string
from cryptolab.exceptions import InputValidationError, ResourceLimitError
from cryptolab.limits import MAX_AUTOCORRELATION_LAGS, MAX_SEQUENCE_ANALYSIS_BITS


@dataclass(frozen=True, slots=True)
class RunCount:
    """Number of cyclic runs for one bit value and run length."""

    bit: int
    length: int
    count: int


@dataclass(frozen=True, slots=True)
class AutocorrelationValue:
    """Periodic bipolar autocorrelation at one lag."""

    lag: int
    value: int
    normalized: float


@dataclass(frozen=True, slots=True)
class SequenceAnalysisResult:
    """Balance, period, cyclic runs, and periodic autocorrelation."""

    sequence: str
    length: int
    zeros: int
    ones: int
    balance_difference: int
    balanced: bool
    fundamental_period: int
    runs: tuple[RunCount, ...]
    autocorrelation: tuple[AutocorrelationValue, ...]
    autocorrelation_truncated: bool


def _divisors(value: int) -> tuple[int, ...]:
    lower: list[int] = []
    upper: list[int] = []
    candidate = 1
    while candidate * candidate <= value:
        if value % candidate == 0:
            lower.append(candidate)
            paired = value // candidate
            if paired != candidate:
                upper.append(paired)
        candidate += 1
    return tuple(lower + list(reversed(upper)))


def _fundamental_period(sequence: str) -> int:
    length = len(sequence)
    for period in _divisors(length):
        if all(sequence[index] == sequence[index % period] for index in range(length)):
            return period
    return length  # pragma: no cover


def _cyclic_runs(sequence: str) -> tuple[RunCount, ...]:
    length = len(sequence)
    if len(set(sequence)) == 1:
        return (RunCount(bit=int(sequence[0]), length=length, count=1),)

    boundary = next(
        index for index in range(length) if sequence[index] != sequence[(index - 1) % length]
    )
    rotated = sequence[boundary:] + sequence[:boundary]
    counts: dict[tuple[int, int], int] = {}
    run_bit = rotated[0]
    run_length = 1
    for symbol in rotated[1:]:
        if symbol == run_bit:
            run_length += 1
            continue
        key = (int(run_bit), run_length)
        counts[key] = counts.get(key, 0) + 1
        run_bit = symbol
        run_length = 1
    key = (int(run_bit), run_length)
    counts[key] = counts.get(key, 0) + 1
    return tuple(
        RunCount(bit=bit, length=run_length_value, count=count)
        for (bit, run_length_value), count in sorted(counts.items())
    )


def analyze_binary_sequence(
    sequence: str,
    *,
    max_lag: int | None = None,
) -> SequenceAnalysisResult:
    """Analyze one non-empty finite binary sequence using periodic conventions."""

    validated = validate_bit_string(sequence, label="binary sequence")
    if len(validated) > MAX_SEQUENCE_ANALYSIS_BITS:
        raise ResourceLimitError(
            f"Binary sequence analysis accepts at most {MAX_SEQUENCE_ANALYSIS_BITS} bits."
        )
    if max_lag is not None and max_lag < 0:
        raise InputValidationError("Maximum autocorrelation lag must be non-negative.")

    length = len(validated)
    requested_max = length - 1 if max_lag is None else min(max_lag, length - 1)
    effective_max = min(requested_max, MAX_AUTOCORRELATION_LAGS)
    autocorrelation_values: list[AutocorrelationValue] = []
    for lag in range(effective_max + 1):
        value = sum(
            1 if validated[index] == validated[(index + lag) % length] else -1
            for index in range(length)
        )
        autocorrelation_values.append(
            AutocorrelationValue(lag=lag, value=value, normalized=value / length)
        )
    autocorrelation = tuple(autocorrelation_values)
    zeros = validated.count("0")
    ones = validated.count("1")
    difference = abs(ones - zeros)
    return SequenceAnalysisResult(
        sequence=validated,
        length=length,
        zeros=zeros,
        ones=ones,
        balance_difference=difference,
        balanced=difference <= 1,
        fundamental_period=_fundamental_period(validated),
        runs=_cyclic_runs(validated),
        autocorrelation=autocorrelation,
        autocorrelation_truncated=effective_max < length - 1,
    )
