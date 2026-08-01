from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from cryptolab.mathematics.diophantine import solve_diophantine

small = st.integers(min_value=-10_000, max_value=10_000)
parameter = st.integers(min_value=-100, max_value=100)


@given(a=small, b=small, x=small, y=small, t=parameter)
def test_constructed_equation_has_verified_solution(
    a: int,
    b: int,
    x: int,
    y: int,
    t: int,
) -> None:
    c = a * x + b * y
    result = solve_diophantine(a, b, c)
    assert result.solvable
    if result.x0 is not None:
        solution_x, solution_y = result.solution_at(t)
        assert a * solution_x + b * solution_y == c
