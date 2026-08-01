"""Educational solvers for linear Diophantine equations in two variables."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from math import gcd as math_gcd

from cryptolab.exceptions import ResourceLimitError
from cryptolab.limits import MAX_INTEGER_BITS
from cryptolab.mathematics.integers import extended_gcd


class DiophantineSolutionKind(StrEnum):
    """Classification of the integer solution set."""

    NONE = "none"
    PARAMETRIC = "parametric"
    ALL_INTEGER_PAIRS = "all-integer-pairs"


@dataclass(frozen=True, slots=True)
class ReducedDiophantineEquation:
    """Equivalent equation obtained by division by a common factor and sign normalization."""

    a: int
    b: int
    c: int
    scale_factor: int


@dataclass(frozen=True, slots=True)
class DiophantineResult:
    """Complete classification and canonical description of ``ax + by = c``."""

    a: int
    b: int
    c: int
    gcd: int
    kind: DiophantineSolutionKind
    reduced: ReducedDiophantineEquation
    x0: int | None
    y0: int | None
    step_x: int | None
    step_y: int | None

    @property
    def solvable(self) -> bool:
        """Return whether the equation has at least one integer solution."""

        return self.kind is not DiophantineSolutionKind.NONE

    @property
    def particular_solution_holds(self) -> bool:
        """Verify the stored particular solution when one exists."""

        if self.kind is not DiophantineSolutionKind.PARAMETRIC:
            return self.kind is DiophantineSolutionKind.ALL_INTEGER_PAIRS
        if self.x0 is None or self.y0 is None:  # pragma: no cover
            return False
        return self.a * self.x0 + self.b * self.y0 == self.c

    def solution_at(self, parameter: int) -> tuple[int, int]:
        """Return the solution corresponding to an integer parameter value."""

        if self.kind is not DiophantineSolutionKind.PARAMETRIC:
            raise ValueError("A parameterized solution is not available for this equation.")
        x0 = self.x0
        y0 = self.y0
        step_x = self.step_x
        step_y = self.step_y
        if x0 is None or y0 is None or step_x is None or step_y is None:  # pragma: no cover
            raise ArithmeticError("Internal Diophantine result invariant failure.")
        return (x0 + step_x * parameter, y0 + step_y * parameter)


def _validate_integer_size(*values: int) -> None:
    for value in values:
        if value.bit_length() > MAX_INTEGER_BITS:
            raise ResourceLimitError(
                f"Integer input exceeds the {MAX_INTEGER_BITS}-bit general arithmetic limit."
            )


def reduce_equation(a: int, b: int, c: int) -> ReducedDiophantineEquation:
    """Return a sign-normalized equation divided by the gcd of all coefficients."""

    _validate_integer_size(a, b, c)
    common = math_gcd(abs(a), abs(b), abs(c))
    scale_factor = common if common != 0 else 1
    reduced_a = a // scale_factor
    reduced_b = b // scale_factor
    reduced_c = c // scale_factor

    first_nonzero = next(
        (value for value in (reduced_a, reduced_b, reduced_c) if value != 0),
        0,
    )
    if first_nonzero < 0:
        reduced_a = -reduced_a
        reduced_b = -reduced_b
        reduced_c = -reduced_c

    return ReducedDiophantineEquation(
        a=reduced_a,
        b=reduced_b,
        c=reduced_c,
        scale_factor=scale_factor,
    )


def solve_diophantine(a: int, b: int, c: int) -> DiophantineResult:
    """Solve ``ax + by = c`` over the integers and return its complete solution family."""

    _validate_integer_size(a, b, c)
    reduced = reduce_equation(a, b, c)

    if a == 0 and b == 0:
        kind = DiophantineSolutionKind.ALL_INTEGER_PAIRS if c == 0 else DiophantineSolutionKind.NONE
        return DiophantineResult(
            a=a,
            b=b,
            c=c,
            gcd=0,
            kind=kind,
            reduced=reduced,
            x0=None,
            y0=None,
            step_x=None,
            step_y=None,
        )

    divisor = math_gcd(a, b)
    if c % divisor != 0:
        return DiophantineResult(
            a=a,
            b=b,
            c=c,
            gcd=divisor,
            kind=DiophantineSolutionKind.NONE,
            reduced=reduced,
            x0=None,
            y0=None,
            step_x=None,
            step_y=None,
        )

    bezout = extended_gcd(a, b)
    multiplier = c // divisor
    x0 = bezout.x * multiplier
    y0 = bezout.y * multiplier
    result = DiophantineResult(
        a=a,
        b=b,
        c=c,
        gcd=divisor,
        kind=DiophantineSolutionKind.PARAMETRIC,
        reduced=reduced,
        x0=x0,
        y0=y0,
        step_x=b // divisor,
        step_y=-(a // divisor),
    )
    if not result.particular_solution_holds:  # pragma: no cover
        raise ArithmeticError("Internal Diophantine-solution invariant failure.")
    return result


def verify_diophantine_solution(a: int, b: int, c: int, x: int, y: int) -> bool:
    """Return whether ``(x, y)`` is an integer solution of ``ax + by = c``."""

    _validate_integer_size(a, b, c, x, y)
    return a * x + b * y == c
