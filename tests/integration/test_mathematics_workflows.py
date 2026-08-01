from __future__ import annotations

from cryptolab.mathematics.diophantine import solve_diophantine
from cryptolab.mathematics.modular import (
    Congruence,
    generalized_crt,
    modular_inverse,
    solve_linear_congruence,
)


def test_bezout_diophantine_inverse_connection() -> None:
    equation = solve_diophantine(33, 17, 1)
    inverse = modular_inverse(33, 17)
    assert equation.x0 is not None
    assert inverse.inverse == equation.x0 % 17


def test_linear_congruence_and_crt_workflow() -> None:
    linear = solve_linear_congruence(3, 5, 7)
    assert linear.solutions == (4,)
    result = generalized_crt((Congruence(linear.solutions[0], 7), Congruence(0, 6)))
    assert result.solvable
    assert result.residue == 18
    assert result.modulus == 42
