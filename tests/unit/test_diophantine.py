from __future__ import annotations

import pytest

from cryptolab.mathematics.diophantine import (
    DiophantineSolutionKind,
    reduce_equation,
    solve_diophantine,
    verify_diophantine_solution,
)


def test_solve_standard_equation() -> None:
    result = solve_diophantine(33, 17, 1)
    assert result.kind is DiophantineSolutionKind.PARAMETRIC
    assert result.gcd == 1
    assert result.particular_solution_holds
    for parameter in range(-5, 6):
        x, y = result.solution_at(parameter)
        assert 33 * x + 17 * y == 1


def test_unsolvable_equation() -> None:
    result = solve_diophantine(6, -9, 8)
    assert result.kind is DiophantineSolutionKind.NONE
    assert not result.solvable
    assert result.x0 is None


def test_all_integer_pairs() -> None:
    result = solve_diophantine(0, 0, 0)
    assert result.kind is DiophantineSolutionKind.ALL_INTEGER_PAIRS
    assert result.particular_solution_holds


def test_zero_coefficients_inconsistent() -> None:
    result = solve_diophantine(0, 0, 5)
    assert result.kind is DiophantineSolutionKind.NONE


def test_one_zero_coefficient() -> None:
    result = solve_diophantine(0, -7, 21)
    assert result.kind is DiophantineSolutionKind.PARAMETRIC
    assert result.y0 == -3
    assert result.step_y == 0
    assert result.solution_at(8)[1] == -3


def test_equation_reduction_and_sign_normalization() -> None:
    reduced = reduce_equation(-6, 9, -30)
    assert (reduced.a, reduced.b, reduced.c) == (2, -3, 10)
    assert reduced.scale_factor == 3


def test_verify_candidate_solution() -> None:
    assert verify_diophantine_solution(2, -5, 1, 3, 1)
    assert not verify_diophantine_solution(2, -5, 1, 0, 0)


def test_solution_at_rejects_non_parametric_result() -> None:
    result = solve_diophantine(2, 4, 1)
    with pytest.raises(ValueError, match="parameterized solution"):
        result.solution_at(0)
