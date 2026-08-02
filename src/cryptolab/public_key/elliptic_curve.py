"""Transparent elliptic-curve arithmetic over deliberately small prime fields."""

from __future__ import annotations

from dataclasses import dataclass

from cryptolab.exceptions import (
    InputValidationError,
    MathematicalDomainError,
    ResourceLimitError,
)
from cryptolab.limits import MAX_EDUCATIONAL_EC_PRIME, MAX_TRACE_ROWS
from cryptolab.mathematics.integers import is_prime
from cryptolab.mathematics.modular import modular_inverse

MIN_EDUCATIONAL_EC_PRIME = 5
MAX_EDUCATIONAL_EC_SCALAR = 1_000_000
POINT_INFINITY_TOKEN = "infinity"  # noqa: S105
POINT_TOKEN_PARTS = 2


@dataclass(frozen=True, slots=True)
class EllipticCurve:
    """A short-Weierstrass curve ``y^2 = x^3 + ax + b`` over ``F_p``."""

    prime: int
    a: int
    b: int
    nonsingularity_value: int


@dataclass(frozen=True, slots=True)
class ECPoint:
    """An affine curve point or the distinguished point at infinity."""

    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        """Return whether this value is the point at infinity."""

        return self.x is None and self.y is None


POINT_AT_INFINITY = ECPoint(None, None)


@dataclass(frozen=True, slots=True)
class ECCurveInspectionResult:
    """An enumerated small elliptic curve and its finite group order."""

    curve: EllipticCurve
    finite_points: tuple[ECPoint, ...]
    group_order: int


@dataclass(frozen=True, slots=True)
class ECNegationResult:
    """Point negation on a small educational curve."""

    curve: EllipticCurve
    point: ECPoint
    negated: ECPoint


@dataclass(frozen=True, slots=True)
class ECAdditionTrace:
    """Intermediate values for affine point addition or doubling."""

    operation: str
    numerator: int | None
    denominator: int | None
    denominator_inverse: int | None
    slope: int | None
    result: ECPoint


@dataclass(frozen=True, slots=True)
class ECAdditionResult:
    """One point-addition result and its transparent affine trace."""

    curve: EllipticCurve
    left: ECPoint
    right: ECPoint
    trace: ECAdditionTrace


@dataclass(frozen=True, slots=True)
class ECScalarStep:
    """One right-to-left double-and-add step."""

    remaining_scalar: int
    bit: int
    accumulator_before: ECPoint
    addend_before: ECPoint
    accumulator_after: ECPoint
    addend_after: ECPoint


@dataclass(frozen=True, slots=True)
class ECScalarMultiplicationResult:
    """One scalar multiplication and its double-and-add trace."""

    curve: EllipticCurve
    scalar: int
    point: ECPoint
    result: ECPoint
    steps: tuple[ECScalarStep, ...]


@dataclass(frozen=True, slots=True)
class ECPointOrderResult:
    """The order and generated subgroup of one point."""

    curve: EllipticCurve
    point: ECPoint
    order: int
    subgroup: tuple[ECPoint, ...]
    curve_group_order: int
    divides_group_order: bool


def point_to_token(point: ECPoint) -> str:
    """Return the canonical CLI token for a point."""

    if point.is_infinity:
        return POINT_INFINITY_TOKEN
    if point.x is None or point.y is None:  # pragma: no cover
        raise ArithmeticError("Internal incomplete elliptic-curve point.")
    return f"{point.x}:{point.y}"


def parse_point_token(token: str) -> ECPoint:
    """Parse ``x:y`` or the canonical ``infinity`` token."""

    normalized = token.strip().lower()
    if normalized == POINT_INFINITY_TOKEN:
        return POINT_AT_INFINITY
    pieces = token.split(":")
    if len(pieces) != POINT_TOKEN_PARTS:
        raise InputValidationError("Use POINT as x:y or the literal infinity.")
    try:
        return ECPoint(int(pieces[0]), int(pieces[1]))
    except ValueError as error:
        raise InputValidationError("Elliptic-curve point coordinates must be integers.") from error


def build_elliptic_curve(prime: int, a: int, b: int) -> EllipticCurve:
    """Validate and construct a deliberately small non-singular curve."""

    if prime < MIN_EDUCATIONAL_EC_PRIME:
        raise MathematicalDomainError(
            f"Educational elliptic curves require an odd prime p >= {MIN_EDUCATIONAL_EC_PRIME}."
        )
    if prime > MAX_EDUCATIONAL_EC_PRIME:
        raise ResourceLimitError(
            "Educational elliptic-curve arithmetic accepts prime moduli at most "
            f"{MAX_EDUCATIONAL_EC_PRIME}."
        )
    primality = is_prime(prime)
    if not primality.is_prime:
        detail = "" if primality.divisor is None else f"; divisor {primality.divisor}"
        raise MathematicalDomainError(f"Elliptic-curve modulus must be prime{detail}.")

    normalized_a = a % prime
    normalized_b = b % prime
    nonsingularity_value = (
        4 * pow(normalized_a, 3, prime) + 27 * pow(normalized_b, 2, prime)
    ) % prime
    if nonsingularity_value == 0:
        raise MathematicalDomainError(
            "The curve is singular because 4a^3 + 27b^2 is congruent to zero modulo p."
        )
    return EllipticCurve(
        prime=prime,
        a=normalized_a,
        b=normalized_b,
        nonsingularity_value=nonsingularity_value,
    )


def is_point_on_curve(curve: EllipticCurve, point: ECPoint) -> bool:
    """Return whether ``point`` belongs to ``curve`` including infinity."""

    if point.is_infinity:
        return True
    if point.x is None or point.y is None:
        return False
    x = point.x % curve.prime
    y = point.y % curve.prime
    return pow(y, 2, curve.prime) == (pow(x, 3, curve.prime) + curve.a * x + curve.b) % curve.prime


def normalize_point(curve: EllipticCurve, point: ECPoint) -> ECPoint:
    """Validate a point and return canonical coordinates in ``0..p-1``."""

    if point.is_infinity:
        return POINT_AT_INFINITY
    if point.x is None or point.y is None:
        raise InputValidationError("A finite elliptic-curve point requires both coordinates.")
    normalized = ECPoint(point.x % curve.prime, point.y % curve.prime)
    if not is_point_on_curve(curve, normalized):
        raise MathematicalDomainError(
            f"Point {point_to_token(normalized)} is not on the selected elliptic curve."
        )
    return normalized


def enumerate_curve_points(curve: EllipticCurve) -> ECCurveInspectionResult:
    """Enumerate all affine points using a quadratic-residue lookup."""

    roots: dict[int, list[int]] = {}
    for y in range(curve.prime):
        roots.setdefault(pow(y, 2, curve.prime), []).append(y)

    points: list[ECPoint] = []
    for x in range(curve.prime):
        right = (pow(x, 3, curve.prime) + curve.a * x + curve.b) % curve.prime
        points.extend(ECPoint(x, y) for y in roots.get(right, ()))

    finite_points = tuple(points)
    return ECCurveInspectionResult(
        curve=curve,
        finite_points=finite_points,
        group_order=len(finite_points) + 1,
    )


def negate_point(curve: EllipticCurve, point: ECPoint) -> ECNegationResult:
    """Return the additive inverse of one curve point."""

    normalized = normalize_point(curve, point)
    if normalized.is_infinity:
        negated = POINT_AT_INFINITY
    else:
        if normalized.x is None or normalized.y is None:  # pragma: no cover
            raise ArithmeticError("Internal incomplete elliptic-curve point.")
        negated = ECPoint(normalized.x, (-normalized.y) % curve.prime)
    return ECNegationResult(curve=curve, point=normalized, negated=negated)


def add_points(curve: EllipticCurve, left: ECPoint, right: ECPoint) -> ECAdditionResult:
    """Add two points using transparent affine formulas."""

    left = normalize_point(curve, left)
    right = normalize_point(curve, right)

    if left.is_infinity:
        return ECAdditionResult(
            curve,
            left,
            right,
            ECAdditionTrace("identity-left", None, None, None, None, right),
        )
    if right.is_infinity:
        return ECAdditionResult(
            curve,
            left,
            right,
            ECAdditionTrace("identity-right", None, None, None, None, left),
        )

    if left.x is None or left.y is None or right.x is None or right.y is None:  # pragma: no cover
        raise ArithmeticError("Internal incomplete elliptic-curve point.")

    if left.x == right.x and (left.y + right.y) % curve.prime == 0:
        operation = "vertical-tangent" if left == right else "inverse-pair"
        return ECAdditionResult(
            curve,
            left,
            right,
            ECAdditionTrace(operation, None, None, None, None, POINT_AT_INFINITY),
        )

    if left == right:
        operation = "doubling"
        numerator = (3 * left.x * left.x + curve.a) % curve.prime
        denominator = (2 * left.y) % curve.prime
    else:
        operation = "addition"
        numerator = (right.y - left.y) % curve.prime
        denominator = (right.x - left.x) % curve.prime

    inverse_result = modular_inverse(denominator, curve.prime)
    if not inverse_result.exists or inverse_result.inverse is None:  # pragma: no cover
        raise ArithmeticError("Internal elliptic-curve denominator is not invertible.")
    slope = numerator * inverse_result.inverse % curve.prime
    result_x = (slope * slope - left.x - right.x) % curve.prime
    result_y = (slope * (left.x - result_x) - left.y) % curve.prime
    result = ECPoint(result_x, result_y)
    if not is_point_on_curve(curve, result):  # pragma: no cover
        raise ArithmeticError("Internal elliptic-curve addition invariant failure.")
    return ECAdditionResult(
        curve=curve,
        left=left,
        right=right,
        trace=ECAdditionTrace(
            operation=operation,
            numerator=numerator,
            denominator=denominator,
            denominator_inverse=inverse_result.inverse,
            slope=slope,
            result=result,
        ),
    )


def scalar_multiply(
    curve: EllipticCurve,
    scalar: int,
    point: ECPoint,
) -> ECScalarMultiplicationResult:
    """Multiply a point by an integer with right-to-left double-and-add."""

    if abs(scalar) > MAX_EDUCATIONAL_EC_SCALAR:
        raise ResourceLimitError(
            "Educational elliptic-curve scalar magnitude must not exceed "
            f"{MAX_EDUCATIONAL_EC_SCALAR}."
        )
    point = normalize_point(curve, point)
    effective_point = point
    remaining = scalar
    if scalar < 0:
        effective_point = negate_point(curve, point).negated
        remaining = -scalar

    accumulator = POINT_AT_INFINITY
    addend = effective_point
    steps: list[ECScalarStep] = []
    while remaining:
        accumulator_before = accumulator
        addend_before = addend
        bit = remaining & 1
        if bit:
            accumulator = add_points(curve, accumulator, addend).trace.result
        addend = add_points(curve, addend, addend).trace.result
        steps.append(
            ECScalarStep(
                remaining_scalar=remaining,
                bit=bit,
                accumulator_before=accumulator_before,
                addend_before=addend_before,
                accumulator_after=accumulator,
                addend_after=addend,
            )
        )
        if len(steps) > MAX_TRACE_ROWS:  # pragma: no cover
            raise ResourceLimitError("Elliptic-curve scalar trace exceeds the row limit.")
        remaining >>= 1

    return ECScalarMultiplicationResult(
        curve=curve,
        scalar=scalar,
        point=point,
        result=accumulator,
        steps=tuple(steps),
    )


def point_order(curve: EllipticCurve, point: ECPoint) -> ECPointOrderResult:
    """Enumerate the cyclic subgroup generated by one point."""

    point = normalize_point(curve, point)
    inspection = enumerate_curve_points(curve)
    if point.is_infinity:
        return ECPointOrderResult(
            curve=curve,
            point=point,
            order=1,
            subgroup=(POINT_AT_INFINITY,),
            curve_group_order=inspection.group_order,
            divides_group_order=True,
        )

    subgroup: list[ECPoint] = []
    current = POINT_AT_INFINITY
    for _ in range(1, inspection.group_order + 1):
        current = add_points(curve, current, point).trace.result
        subgroup.append(current)
        if current.is_infinity:
            break
    else:  # pragma: no cover
        raise ArithmeticError("Internal elliptic-curve point-order invariant failure.")

    order = len(subgroup)
    return ECPointOrderResult(
        curve=curve,
        point=point,
        order=order,
        subgroup=tuple(subgroup),
        curve_group_order=inspection.group_order,
        divides_group_order=inspection.group_order % order == 0,
    )
