"""Compute SageMath reference results for one dynamic CryptoLab request."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping
from typing import Any

from sage.all import (
    GF,
    EllipticCurve,
    Integer,
    Zmod,
    euler_phi,
    factor,
    gcd,
    inverse_mod,
    lcm,
    power_mod,
    xgcd,
)
from sage.version import version as sage_version

JsonObject = dict[str, Any]
ReferenceComputer = Callable[[Mapping[str, Any]], JsonObject]


class ReferenceComputationError(RuntimeError):
    """Raised when a request is malformed or unsupported."""


def _integer(value: Any, label: str) -> Integer:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReferenceComputationError(f"{label} must be an integer.")
    return Integer(value)


def _point_to_json(point: Any) -> JsonObject:
    if point.is_zero():
        return {"x": None, "y": None}
    return {"x": int(point[0]), "y": int(point[1])}


def _curve(inputs: Mapping[str, Any]) -> tuple[Any, Any]:
    prime = _integer(inputs["prime"], "prime")
    field = GF(prime)
    curve = EllipticCurve(
        field,
        [
            _integer(inputs["a"], "a"),
            _integer(inputs["b"], "b"),
        ],
    )
    return field, curve


def _curve_point(curve: Any, field: Any, value: Mapping[str, Any]) -> Any:
    x = value.get("x")
    y = value.get("y")
    if x is None and y is None:
        return curve(0)
    return curve(field(_integer(x, "point.x")), field(_integer(y, "point.y")))


def _factor(inputs: Mapping[str, Any]) -> JsonObject:
    n = _integer(inputs["n"], "n")
    sign = -1 if n < 0 else 1
    factors = [
        {"prime": int(prime), "exponent": int(exponent)} for prime, exponent in factor(abs(n))
    ]
    reconstructed = Integer(sign)
    for item in factors:
        reconstructed *= Integer(item["prime"]) ** Integer(item["exponent"])
    return {"sign": sign, "factors": factors, "reconstructed": int(reconstructed)}


def _gcd(inputs: Mapping[str, Any]) -> JsonObject:
    return {"value": int(gcd(_integer(inputs["a"], "a"), _integer(inputs["b"], "b")))}


def _lcm(inputs: Mapping[str, Any]) -> JsonObject:
    return {"value": int(lcm(_integer(inputs["a"], "a"), _integer(inputs["b"], "b")))}


def _extended_gcd(inputs: Mapping[str, Any]) -> JsonObject:
    a = _integer(inputs["a"], "a")
    b = _integer(inputs["b"], "b")
    divisor, coefficient_x, coefficient_y = xgcd(a, b)
    return {
        "gcd": int(divisor),
        "bezout_value": int(a * coefficient_x + b * coefficient_y),
    }


def _diophantine(inputs: Mapping[str, Any]) -> JsonObject:
    a = _integer(inputs["a"], "a")
    b = _integer(inputs["b"], "b")
    c = _integer(inputs["c"], "c")
    if a == 0 and b == 0:
        solvable = c == 0
        return {
            "gcd": 0,
            "kind": "all-integer-pairs" if solvable else "none",
            "solvable": bool(solvable),
            "step_x": None,
            "step_y": None,
            "particular_solution_holds": bool(solvable),
        }
    divisor = gcd(a, b)
    solvable = c % divisor == 0
    return {
        "gcd": int(divisor),
        "kind": "parametric" if solvable else "none",
        "solvable": bool(solvable),
        "step_x": int(b // divisor) if solvable else None,
        "step_y": int(-(a // divisor)) if solvable else None,
        "particular_solution_holds": bool(solvable),
    }


def _modular_inverse(inputs: Mapping[str, Any]) -> JsonObject:
    value = _integer(inputs["value"], "value")
    modulus = _integer(inputs["modulus"], "modulus")
    divisor = gcd(value, modulus)
    exists = divisor == 1
    return {
        "exists": bool(exists),
        "gcd": int(divisor),
        "inverse": int(inverse_mod(value, modulus)) if exists else None,
    }


def _generalized_crt(congruences: list[Mapping[str, Any]]) -> JsonObject:
    if not congruences:
        raise ReferenceComputationError("At least one congruence is required.")
    first = congruences[0]
    residue = _integer(first["residue"], "residue")
    modulus = _integer(first["modulus"], "modulus")
    residue %= modulus
    for item in congruences[1:]:
        right_residue = _integer(item["residue"], "residue")
        right_modulus = _integer(item["modulus"], "modulus")
        right_residue %= right_modulus
        divisor, coefficient, _ = xgcd(modulus, right_modulus)
        difference = right_residue - residue
        if difference % divisor != 0:
            return {"solvable": False, "residue": None, "modulus": None}
        reduced_modulus = right_modulus // divisor
        multiplier = (difference // divisor * coefficient) % reduced_modulus
        merged_modulus = modulus * reduced_modulus
        residue = (residue + modulus * multiplier) % merged_modulus
        modulus = merged_modulus
    return {"solvable": True, "residue": int(residue), "modulus": int(modulus)}


def _crt(inputs: Mapping[str, Any]) -> JsonObject:
    raw = inputs["congruences"]
    if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
        raise ReferenceComputationError("congruences must be a list of objects.")
    return _generalized_crt(raw)


def _algebra_order(inputs: Mapping[str, Any]) -> JsonObject:
    element = _integer(inputs["element"], "element")
    modulus = _integer(inputs["modulus"], "modulus")
    operation = inputs["operation"]
    normalized = element % modulus
    if operation == "additive":
        return {
            "normalized_element": int(normalized),
            "identity": 0,
            "ambient_group_order": int(modulus),
            "order": int(modulus // gcd(normalized, modulus)),
        }
    if operation == "multiplicative":
        residue = Zmod(modulus)(normalized)
        return {
            "normalized_element": int(normalized),
            "identity": 1,
            "ambient_group_order": int(euler_phi(modulus)),
            "order": int(residue.multiplicative_order()),
        }
    raise ReferenceComputationError(f"Unsupported group operation: {operation}")


def _primitive_roots(inputs: Mapping[str, Any]) -> JsonObject:
    modulus = _integer(inputs["modulus"], "modulus")
    ring = Zmod(modulus)
    generators = [
        value
        for value in range(1, int(modulus))
        if gcd(value, modulus) == 1 and int(ring(value).multiplicative_order()) == int(modulus - 1)
    ]
    return {
        "ambient_group_order": int(modulus - 1),
        "cyclic": bool(generators),
        "generators": generators,
    }


def _rsa_key(inputs: Mapping[str, Any]) -> tuple[Integer, ...]:
    p = _integer(inputs["p"], "p")
    q = _integer(inputs["q"], "q")
    public_exponent = _integer(inputs["e"], "e")
    modulus = p * q
    totient = (p - 1) * (q - 1)
    carmichael = lcm(p - 1, q - 1)
    private_exponent = inverse_mod(public_exponent, totient)
    return p, q, public_exponent, modulus, totient, carmichael, private_exponent


def _rsa_inspect(inputs: Mapping[str, Any]) -> JsonObject:
    p, q, public_exponent, modulus, totient, carmichael, private_exponent = _rsa_key(inputs)
    return {
        "p": int(p),
        "q": int(q),
        "n": int(modulus),
        "phi": int(totient),
        "carmichael": int(carmichael),
        "e": int(public_exponent),
        "d": int(private_exponent),
        "d_carmichael": int(inverse_mod(public_exponent, carmichael)),
        "dp": int(private_exponent % (p - 1)),
        "dq": int(private_exponent % (q - 1)),
        "q_inverse_mod_p": int(inverse_mod(q, p)),
        "p_inverse_mod_q": int(inverse_mod(p, q)),
    }


def _rsa_encrypt(inputs: Mapping[str, Any]) -> JsonObject:
    return {
        "output_value": int(
            power_mod(
                _integer(inputs["value"], "value"),
                _integer(inputs["exponent"], "exponent"),
                _integer(inputs["modulus"], "modulus"),
            )
        )
    }


def _rsa_decrypt(inputs: Mapping[str, Any]) -> JsonObject:
    ciphertext = _integer(inputs["ciphertext"], "ciphertext")
    p, q, _public_exponent, modulus, _totient, _carmichael, private_exponent = _rsa_key(inputs)
    standard = power_mod(ciphertext, private_exponent, modulus)
    m1 = power_mod(ciphertext, private_exponent % (p - 1), p)
    m2 = power_mod(ciphertext, private_exponent % (q - 1), q)
    h = (inverse_mod(q, p) * (m1 - m2)) % p
    crt_plaintext = (m2 + h * q) % modulus
    return {
        "plaintext": int(standard),
        "standard_plaintext": int(standard),
        "crt_plaintext": int(crt_plaintext),
        "crt_matches_standard": bool(crt_plaintext == standard),
    }


def _multiplicative_order(value: Integer, modulus: Integer) -> int:
    return int(Zmod(modulus)(value).multiplicative_order())


def _dh_group(inputs: Mapping[str, Any]) -> JsonObject:
    prime = _integer(inputs["prime"], "prime")
    generator = _integer(inputs["generator"], "generator")
    order = _multiplicative_order(generator, prime)
    group_order = int(prime - 1)
    return {
        "is_prime_modulus": bool(prime.is_prime()),
        "group_order": group_order,
        "generator_order": order,
        "is_generator": order == group_order,
    }


def _dh_exchange(inputs: Mapping[str, Any]) -> JsonObject:
    prime = _integer(inputs["prime"], "prime")
    generator = _integer(inputs["generator"], "generator")
    alice_private = _integer(inputs["alice_private"], "alice_private")
    bob_private = _integer(inputs["bob_private"], "bob_private")
    alice_public = power_mod(generator, alice_private, prime)
    bob_public = power_mod(generator, bob_private, prime)
    alice_secret = power_mod(bob_public, alice_private, prime)
    bob_secret = power_mod(alice_public, bob_private, prime)
    return {
        "alice_public": int(alice_public),
        "bob_public": int(bob_public),
        "alice_public_order": _multiplicative_order(alice_public, prime),
        "bob_public_order": _multiplicative_order(bob_public, prime),
        "alice_shared_secret": int(alice_secret),
        "bob_shared_secret": int(bob_secret),
        "shared_secret_matches": bool(alice_secret == bob_secret),
    }


def _ecc_inspect(inputs: Mapping[str, Any]) -> JsonObject:
    field, curve = _curve(inputs)
    points = sorted(
        (_point_to_json(point) for point in curve.points() if not point.is_zero()),
        key=lambda item: (item["x"], item["y"]),
    )
    a = int(_integer(inputs["a"], "a") % field.order())
    b = int(_integer(inputs["b"], "b") % field.order())
    prime = int(field.order())
    return {
        "curve": {
            "a": a,
            "b": b,
            "nonsingularity_value": int((4 * a**3 + 27 * b**2) % prime),
            "prime": prime,
        },
        "finite_points": points,
        "group_order": int(curve.cardinality()),
        "point_at_infinity_included": True,
    }


def _ecc_negate(inputs: Mapping[str, Any]) -> JsonObject:
    field, curve = _curve(inputs)
    point = _curve_point(curve, field, inputs["point"])
    return {"negated": _point_to_json(-point)}


def _ecc_add(inputs: Mapping[str, Any]) -> JsonObject:
    field, curve = _curve(inputs)
    left = _curve_point(curve, field, inputs["left"])
    right = _curve_point(curve, field, inputs["right"])
    return {"point": _point_to_json(left + right)}


def _ecc_multiply(inputs: Mapping[str, Any]) -> JsonObject:
    field, curve = _curve(inputs)
    point = _curve_point(curve, field, inputs["point"])
    scalar = _integer(inputs["scalar"], "scalar")
    return {"point": _point_to_json(scalar * point)}


def _ecc_subgroup(inputs: Mapping[str, Any]) -> JsonObject:
    field, curve = _curve(inputs)
    point = _curve_point(curve, field, inputs["point"])
    order = int(point.order())
    subgroup = [_point_to_json(multiplier * point) for multiplier in range(1, order + 1)]
    group_order = int(curve.cardinality())
    return {
        "curve_group_order": group_order,
        "order": order,
        "divides_group_order": group_order % order == 0,
        "subgroup": subgroup,
    }


COMPUTERS: dict[str, ReferenceComputer] = {
    "integer.factor": _factor,
    "integer.gcd": _gcd,
    "integer.lcm": _lcm,
    "integer.extended-gcd": _extended_gcd,
    "diophantine.solve": _diophantine,
    "modular.inverse": _modular_inverse,
    "modular.crt": _crt,
    "algebra.order": _algebra_order,
    "algebra.primitive-roots": _primitive_roots,
    "public-key.rsa.educational.inspect": _rsa_inspect,
    "public-key.rsa.educational.encrypt": _rsa_encrypt,
    "public-key.rsa.educational.decrypt": _rsa_decrypt,
    "public-key.dh.group": _dh_group,
    "public-key.dh.exchange": _dh_exchange,
    "public-key ecc inspect": _ecc_inspect,
    "public-key.ecc.negate": _ecc_negate,
    "public-key.ecc.add": _ecc_add,
    "public-key.ecc.multiply": _ecc_multiply,
    "public-key.ecc.subgroup": _ecc_subgroup,
}


def _parse_request(payload: Any) -> tuple[str, Mapping[str, Any], ReferenceComputer]:
    if not isinstance(payload, dict):
        raise ReferenceComputationError("Request must be a JSON object.")
    command = payload.get("command")
    inputs = payload.get("inputs")
    if not isinstance(command, str) or not isinstance(inputs, dict):
        raise ReferenceComputationError("Request requires string command and object inputs.")
    computer = COMPUTERS.get(command)
    if computer is None:
        raise ReferenceComputationError(f"Unsupported SageMath reference command: {command}")
    return command, inputs, computer


def main() -> int:
    """Read one request from stdin and return its SageMath result as JSON."""

    try:
        command, inputs, computer = _parse_request(json.load(sys.stdin))
        response = {
            "schema_version": "1.0",
            "command": command,
            "sagemath_version": sage_version,
            "result": computer(inputs),
        }
    except (
        KeyError,
        TypeError,
        ValueError,
        ArithmeticError,
        ReferenceComputationError,
    ) as error:
        print(json.dumps({"error": str(error)}))
        return 1

    print(json.dumps(response, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
