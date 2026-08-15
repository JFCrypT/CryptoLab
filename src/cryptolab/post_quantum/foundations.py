"""Small educational constructions used to explain post-quantum algebra."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.exceptions import InputValidationError, ResourceLimitError

MAX_RING_DEGREE = 32
MAX_TOY_LWE_DIMENSION = 16
MAX_EDUCATIONAL_MODULUS = 65_521
MINIMUM_EDUCATIONAL_MODULUS = 2


@dataclass(frozen=True, slots=True)
class NegacyclicMultiplicationTerm:
    """One contribution before reduction by x^n + 1."""

    left_index: int
    right_index: int
    raw_degree: int
    reduced_degree: int
    sign: int
    contribution: int


@dataclass(frozen=True, slots=True)
class NegacyclicMultiplicationResult:
    """Multiplication in Z_q[x]/(x^n + 1) for tiny educational inputs."""

    modulus: int
    degree: int
    left: tuple[int, ...]
    right: tuple[int, ...]
    result: tuple[int, ...]
    terms: tuple[NegacyclicMultiplicationTerm, ...]


@dataclass(frozen=True, slots=True)
class ToyLWERow:
    """One row of a toy Learning With Errors sample."""

    row: tuple[int, ...]
    dot_product: int
    error: int
    value: int


@dataclass(frozen=True, slots=True)
class ToyLWEResult:
    """Tiny b = A*s + e mod q example used only for explanation."""

    modulus: int
    matrix: tuple[tuple[int, ...], ...]
    secret: tuple[int, ...]
    error: tuple[int, ...]
    output: tuple[int, ...]
    rows: tuple[ToyLWERow, ...]


def _validate_modulus(modulus: int) -> None:
    if modulus < MINIMUM_EDUCATIONAL_MODULUS:
        raise InputValidationError("Educational modulus q must be at least 2.")
    if modulus > MAX_EDUCATIONAL_MODULUS:
        raise ResourceLimitError(
            f"Educational modulus q must not exceed {MAX_EDUCATIONAL_MODULUS}."
        )


def _canonical_vector(values: tuple[int, ...], modulus: int) -> tuple[int, ...]:
    return tuple(value % modulus for value in values)


def negacyclic_multiply(
    left: tuple[int, ...],
    right: tuple[int, ...],
    *,
    modulus: int,
) -> NegacyclicMultiplicationResult:
    """Multiply two equal-length coefficient vectors modulo q and x^n + 1."""

    _validate_modulus(modulus)
    if not left or not right:
        raise InputValidationError("Polynomial coefficient vectors must not be empty.")
    if len(left) != len(right):
        raise InputValidationError("Polynomial coefficient vectors must have equal length.")
    if len(left) > MAX_RING_DEGREE:
        raise ResourceLimitError(f"Educational polynomial degree bound is n <= {MAX_RING_DEGREE}.")

    n = len(left)
    canonical_left = _canonical_vector(left, modulus)
    canonical_right = _canonical_vector(right, modulus)
    accumulator = [0] * n
    terms: list[NegacyclicMultiplicationTerm] = []
    for left_index, left_value in enumerate(canonical_left):
        for right_index, right_value in enumerate(canonical_right):
            raw_degree = left_index + right_index
            if raw_degree < n:
                reduced_degree = raw_degree
                sign = 1
            else:
                reduced_degree = raw_degree - n
                sign = -1
            contribution = sign * left_value * right_value
            accumulator[reduced_degree] += contribution
            terms.append(
                NegacyclicMultiplicationTerm(
                    left_index=left_index,
                    right_index=right_index,
                    raw_degree=raw_degree,
                    reduced_degree=reduced_degree,
                    sign=sign,
                    contribution=contribution,
                )
            )

    result = tuple(value % modulus for value in accumulator)
    return NegacyclicMultiplicationResult(
        modulus=modulus,
        degree=n,
        left=canonical_left,
        right=canonical_right,
        result=result,
        terms=tuple(terms),
    )


def toy_lwe_sample(
    matrix: tuple[tuple[int, ...], ...],
    secret: tuple[int, ...],
    error: tuple[int, ...],
    *,
    modulus: int,
) -> ToyLWEResult:
    """Compute a tiny educational LWE-style sample b = A*s + e mod q."""

    _validate_modulus(modulus)
    if not matrix or not secret:
        raise InputValidationError("Toy LWE matrix and secret vector must not be empty.")
    if len(matrix) > MAX_TOY_LWE_DIMENSION or len(secret) > MAX_TOY_LWE_DIMENSION:
        raise ResourceLimitError(f"Toy LWE dimensions must not exceed {MAX_TOY_LWE_DIMENSION}.")
    if len(error) != len(matrix):
        raise InputValidationError("Toy LWE error vector length must equal the matrix row count.")
    if any(len(row) != len(secret) for row in matrix):
        raise InputValidationError("Every toy LWE matrix row must match the secret-vector length.")

    canonical_matrix = tuple(_canonical_vector(row, modulus) for row in matrix)
    canonical_secret = _canonical_vector(secret, modulus)
    rows: list[ToyLWERow] = []
    output: list[int] = []
    for row, error_value in zip(canonical_matrix, error, strict=True):
        dot_product = sum(
            value * secret_value for value, secret_value in zip(row, canonical_secret, strict=True)
        )
        reduced = (dot_product + error_value) % modulus
        rows.append(
            ToyLWERow(
                row=row,
                dot_product=dot_product,
                error=error_value,
                value=reduced,
            )
        )
        output.append(reduced)

    return ToyLWEResult(
        modulus=modulus,
        matrix=canonical_matrix,
        secret=canonical_secret,
        error=error,
        output=tuple(output),
        rows=tuple(rows),
    )
