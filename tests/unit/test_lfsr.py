from __future__ import annotations

import pytest

from cryptolab.exceptions import InputValidationError, ResourceLimitError
from cryptolab.sequences.lfsr import (
    describe_lfsr,
    detect_lfsr_period,
    generate_lfsr,
    next_lfsr_state,
    parse_feedback_polynomial,
    parse_seed,
)


def test_parse_polynomial_and_fixed_convention() -> None:
    polynomial = parse_feedback_polynomial("x^3 + x^2 + 1")
    assert polynomial.degree == 3
    assert polynomial.coefficients == (1, 0, 1, 1)
    assert polynomial.tap_indices == (0, 2)
    assert polynomial.canonical == "x^3+x^2+1"
    seed = parse_seed("101", polynomial.degree)
    next_state, output, feedback = next_lfsr_state(polynomial, seed)
    assert output == 1
    assert feedback == 0
    assert next_state == (0, 1, 0)


def test_lfsr_generation_period_and_diagram() -> None:
    polynomial = parse_feedback_polynomial("x^3+x^2+1")
    seed = parse_seed("101", polynomial.degree)
    generated = generate_lfsr(polynomial, seed, 21)
    assert generated.output == "101001110100111010011"
    assert generated.final_state == seed
    assert len(generated.transitions) == 21

    period = detect_lfsr_period(polynomial, seed)
    assert period.period == 7
    assert period.preperiod == 0
    assert period.is_maximum_length
    assert not period.zero_state

    diagram = describe_lfsr(polynomial)
    assert diagram.stages == ("s_2", "s_1", "s_0")
    assert diagram.tap_stages == ("s_2", "s_0")
    assert diagram.output_stage == "s_0"


def test_zero_state_has_period_one() -> None:
    polynomial = parse_feedback_polynomial("x^3+x^2+1")
    period = detect_lfsr_period(polynomial, (0, 0, 0))
    assert period.period == 1
    assert period.zero_state
    assert not period.is_maximum_length


def test_teaching_exercise_polynomials_have_expected_periods() -> None:
    cases = (
        ("x^4+x^3+1", "1011", 15),
        ("x^5+x^4+x^3+x+1", "01001", 31),
    )
    for polynomial_text, seed_text, expected_period in cases:
        polynomial = parse_feedback_polynomial(polynomial_text)
        seed = parse_seed(seed_text, polynomial.degree)
        assert detect_lfsr_period(polynomial, seed).period == expected_period


def test_lfsr_validation() -> None:
    with pytest.raises(InputValidationError, match="canonical x notation"):
        parse_feedback_polynomial("D^3+D^2+1")
    with pytest.raises(InputValidationError, match="constant coefficient"):
        parse_feedback_polynomial("x^3+x")
    with pytest.raises(InputValidationError, match="repeat terms"):
        parse_feedback_polynomial("x^3+x+1+x")
    with pytest.raises(ResourceLimitError, match="between 2 and 24"):
        parse_feedback_polynomial("x+1")
    polynomial = parse_feedback_polynomial("x^3+x^2+1")
    with pytest.raises(InputValidationError, match="exactly 3 bits"):
        parse_seed("10", polynomial.degree)
    with pytest.raises(InputValidationError, match="positive"):
        generate_lfsr(polynomial, (1, 0, 1), 0)
