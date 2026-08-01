"""Educational Fibonacci LFSR using the fixed CryptoLab bit-ordering convention."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.encoding import validate_bit_string
from cryptolab.exceptions import InputValidationError, ResourceLimitError
from cryptolab.limits import (
    MAX_LFSR_DEGREE,
    MAX_LFSR_SEQUENCE_BITS,
    MAX_TRACE_ROWS,
    MIN_LFSR_DEGREE,
)


@dataclass(frozen=True, slots=True)
class FeedbackPolynomial:
    """Binary connection polynomial with coefficients indexed by exponent."""

    degree: int
    coefficients: tuple[int, ...]
    canonical: str

    @property
    def tap_indices(self) -> tuple[int, ...]:
        """Return feedback exponents below the leading term."""

        return tuple(
            index for index, coefficient in enumerate(self.coefficients[:-1]) if coefficient
        )


@dataclass(frozen=True, slots=True)
class LFSRTransition:
    """One right-shift state transition."""

    time: int
    state_before: tuple[int, ...]
    output_bit: int
    feedback_bit: int
    state_after: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class LFSRGenerationResult:
    """Generated output sequence and available state trace."""

    polynomial: FeedbackPolynomial
    seed: tuple[int, ...]
    length: int
    output: str
    final_state: tuple[int, ...]
    transitions: tuple[LFSRTransition, ...]
    trace_truncated: bool


@dataclass(frozen=True, slots=True)
class LFSRPeriodResult:
    """Cycle structure reached from one seed."""

    polynomial: FeedbackPolynomial
    seed: tuple[int, ...]
    preperiod: int
    period: int
    returns_to_seed: bool
    maximum_nonzero_period: int
    is_maximum_length: bool
    zero_state: bool


@dataclass(frozen=True, slots=True)
class LFSRDiagramResult:
    """Structured register diagram metadata."""

    polynomial: FeedbackPolynomial
    degree: int
    stages: tuple[str, ...]
    output_stage: str
    tap_stages: tuple[str, ...]
    shift_direction: str


def _term_exponent(term: str) -> int:
    if term == "1":
        return 0
    if term == "x":
        return 1
    if term.startswith("x^") and term[2:].isdigit():
        return int(term[2:])
    raise InputValidationError(
        "Feedback polynomial terms must use canonical x notation, for example x^4+x^3+1."
    )


def _canonical_polynomial(exponents: tuple[int, ...]) -> str:
    terms: list[str] = []
    for exponent in sorted(exponents, reverse=True):
        if exponent == 0:
            terms.append("1")
        elif exponent == 1:
            terms.append("x")
        else:
            terms.append(f"x^{exponent}")
    return "+".join(terms)


def parse_feedback_polynomial(value: str) -> FeedbackPolynomial:
    """Parse a canonical binary polynomial such as x^4+x^3+1."""

    normalized = value.replace(" ", "").lower()
    if not normalized:
        raise InputValidationError("Feedback polynomial must not be empty.")
    if "d" in normalized:
        raise InputValidationError("Use canonical x notation for polynomial input, not D notation.")
    raw_terms = normalized.split("+")
    if any(not term for term in raw_terms):
        raise InputValidationError("Feedback polynomial contains an empty term.")
    exponents = tuple(_term_exponent(term) for term in raw_terms)
    if len(set(exponents)) != len(exponents):
        raise InputValidationError("Feedback polynomial must not repeat terms.")
    degree = max(exponents)
    if not MIN_LFSR_DEGREE <= degree <= MAX_LFSR_DEGREE:
        raise ResourceLimitError(
            f"LFSR degree must be between {MIN_LFSR_DEGREE} and {MAX_LFSR_DEGREE}."
        )
    if 0 not in exponents:
        raise InputValidationError("Feedback polynomial must have constant coefficient c0 = 1.")
    coefficients = tuple(1 if exponent in exponents else 0 for exponent in range(degree + 1))
    return FeedbackPolynomial(
        degree=degree,
        coefficients=coefficients,
        canonical=_canonical_polynomial(exponents),
    )


def parse_seed(value: str, degree: int) -> tuple[int, ...]:
    """Parse seed bits as [s_(m-1), ..., s_0]."""

    validated = validate_bit_string(value, label="LFSR seed")
    if len(validated) != degree:
        raise InputValidationError(f"LFSR seed must contain exactly {degree} bits.")
    return tuple(int(symbol) for symbol in validated)


def next_lfsr_state(
    polynomial: FeedbackPolynomial,
    state: tuple[int, ...],
) -> tuple[tuple[int, ...], int, int]:
    """Return next state, output bit, and feedback bit."""

    if len(state) != polynomial.degree:
        raise InputValidationError("LFSR state length must equal the polynomial degree.")
    output_bit = state[-1]
    feedback_bit = 0
    for exponent in polynomial.tap_indices:
        feedback_bit ^= state[polynomial.degree - 1 - exponent]
    return (feedback_bit, *state[:-1]), output_bit, feedback_bit


def generate_lfsr(
    polynomial: FeedbackPolynomial,
    seed: tuple[int, ...],
    length: int,
) -> LFSRGenerationResult:
    """Generate a bounded LFSR output sequence."""

    if length < 1:
        raise InputValidationError("LFSR sequence length must be positive.")
    if length > MAX_LFSR_SEQUENCE_BITS:
        raise ResourceLimitError(
            f"LFSR sequence length must not exceed {MAX_LFSR_SEQUENCE_BITS} bits."
        )
    if len(seed) != polynomial.degree:
        raise InputValidationError("LFSR seed length must equal the polynomial degree.")

    state = seed
    output_bits: list[str] = []
    transitions: list[LFSRTransition] = []
    for time in range(length):
        next_state, output_bit, feedback_bit = next_lfsr_state(polynomial, state)
        output_bits.append(str(output_bit))
        if time < MAX_TRACE_ROWS:
            transitions.append(
                LFSRTransition(
                    time=time,
                    state_before=state,
                    output_bit=output_bit,
                    feedback_bit=feedback_bit,
                    state_after=next_state,
                )
            )
        state = next_state

    return LFSRGenerationResult(
        polynomial=polynomial,
        seed=seed,
        length=length,
        output="".join(output_bits),
        final_state=state,
        transitions=tuple(transitions),
        trace_truncated=length > MAX_TRACE_ROWS,
    )


def detect_lfsr_period(
    polynomial: FeedbackPolynomial,
    seed: tuple[int, ...],
) -> LFSRPeriodResult:
    """Detect preperiod and cycle length with Floyd's constant-memory algorithm."""

    if len(seed) != polynomial.degree:
        raise InputValidationError("LFSR seed length must equal the polynomial degree.")

    def advance(state: tuple[int, ...]) -> tuple[int, ...]:
        return next_lfsr_state(polynomial, state)[0]

    tortoise = advance(seed)
    hare = advance(advance(seed))
    state_bound = 1 << polynomial.degree
    iterations = 0
    while tortoise != hare:
        tortoise = advance(tortoise)
        hare = advance(advance(hare))
        iterations += 1
        if iterations > state_bound:  # pragma: no cover
            raise RuntimeError("Internal LFSR cycle-detection invariant failure.")

    preperiod = 0
    tortoise = seed
    while tortoise != hare:
        tortoise = advance(tortoise)
        hare = advance(hare)
        preperiod += 1

    period = 1
    hare = advance(tortoise)
    while tortoise != hare:
        hare = advance(hare)
        period += 1

    zero_state = not any(seed)
    maximum_nonzero_period = (1 << polynomial.degree) - 1
    return LFSRPeriodResult(
        polynomial=polynomial,
        seed=seed,
        preperiod=preperiod,
        period=period,
        returns_to_seed=preperiod == 0,
        maximum_nonzero_period=maximum_nonzero_period,
        is_maximum_length=not zero_state and preperiod == 0 and period == maximum_nonzero_period,
        zero_state=zero_state,
    )


def describe_lfsr(polynomial: FeedbackPolynomial) -> LFSRDiagramResult:
    """Return register and tap metadata for the fixed CryptoLab convention."""

    stages = tuple(f"s_{index}" for index in range(polynomial.degree - 1, -1, -1))
    tap_stages = tuple(f"s_{index}" for index in sorted(polynomial.tap_indices, reverse=True))
    return LFSRDiagramResult(
        polynomial=polynomial,
        degree=polynomial.degree,
        stages=stages,
        output_stage="s_0",
        tap_stages=tap_stages,
        shift_direction="right",
    )
