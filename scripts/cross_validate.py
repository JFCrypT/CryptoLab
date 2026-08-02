#!/usr/bin/env python3
"""Cross-validate one supported CryptoLab calculation with SageMath."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
SAGE_REFERENCE = ROOT / "sagemath/compute_reference.py"
SUCCESS_MARKER = "CryptoLab/SageMath cross-validation: PASSED"

JsonObject = dict[str, Any]
Canonicalizer = Callable[[Mapping[str, Any], Mapping[str, Any]], JsonObject]


class CrossValidationError(RuntimeError):
    """Raised when the requested cross-validation cannot be completed."""


def _select(*keys: str) -> Canonicalizer:
    def canonicalize(_inputs: Mapping[str, Any], result: Mapping[str, Any]) -> JsonObject:
        return {key: result[key] for key in keys}

    return canonicalize


def _canonical_extended_gcd(inputs: Mapping[str, Any], result: Mapping[str, Any]) -> JsonObject:
    a = int(inputs["a"])
    b = int(inputs["b"])
    x = int(result["x"])
    y = int(result["y"])
    return {
        "gcd": int(result["gcd"]),
        "bezout_value": a * x + b * y,
    }


def _canonical_diophantine(_inputs: Mapping[str, Any], result: Mapping[str, Any]) -> JsonObject:
    return {
        "gcd": result["gcd"],
        "kind": result["kind"],
        "solvable": result["solvable"],
        "step_x": result["step_x"],
        "step_y": result["step_y"],
        "particular_solution_holds": result["particular_solution_holds"],
    }


def _canonical_factor(_inputs: Mapping[str, Any], result: Mapping[str, Any]) -> JsonObject:
    return {
        "sign": result["sign"],
        "factors": result["factors"],
        "reconstructed": result["reconstructed"],
    }


def _canonical_ecc_inspect(_inputs: Mapping[str, Any], result: Mapping[str, Any]) -> JsonObject:
    return {
        "curve": result["curve"],
        "finite_points": result["finite_points"],
        "group_order": result["group_order"],
        "point_at_infinity_included": result["point_at_infinity_included"],
    }


CANONICALIZERS: dict[str, Canonicalizer] = {
    "integer.factor": _canonical_factor,
    "integer.gcd": _select("value"),
    "integer.lcm": _select("value"),
    "integer.extended-gcd": _canonical_extended_gcd,
    "diophantine.solve": _canonical_diophantine,
    "modular.inverse": _select("exists", "gcd", "inverse"),
    "modular.crt": _select("solvable", "residue", "modulus"),
    "algebra.order": _select("normalized_element", "identity", "ambient_group_order", "order"),
    "algebra.primitive-roots": _select("ambient_group_order", "cyclic", "generators"),
    "public-key.rsa.educational.inspect": _select(
        "p",
        "q",
        "n",
        "phi",
        "carmichael",
        "e",
        "d",
        "d_carmichael",
        "dp",
        "dq",
        "q_inverse_mod_p",
        "p_inverse_mod_q",
    ),
    "public-key.rsa.educational.encrypt": _select("output_value"),
    "public-key.rsa.educational.decrypt": _select(
        "plaintext", "standard_plaintext", "crt_plaintext", "crt_matches_standard"
    ),
    "public-key.dh.group": _select(
        "is_prime_modulus", "group_order", "generator_order", "is_generator"
    ),
    "public-key.dh.exchange": _select(
        "alice_public",
        "bob_public",
        "alice_public_order",
        "bob_public_order",
        "alice_shared_secret",
        "bob_shared_secret",
        "shared_secret_matches",
    ),
    "public-key ecc inspect": _canonical_ecc_inspect,
    "public-key.ecc.negate": _select("negated"),
    "public-key.ecc.add": _select("point"),
    "public-key.ecc.multiply": _select("point"),
    "public-key.ecc.subgroup": _select(
        "curve_group_order", "order", "divides_group_order", "subgroup"
    ),
}


def _option_value(arguments: Sequence[str], name: str) -> int:
    for index, argument in enumerate(arguments):
        if argument == name:
            try:
                return int(arguments[index + 1])
            except (IndexError, ValueError) as error:
                raise CrossValidationError(f"{name} requires a decimal integer value.") from error
        prefix = f"{name}="
        if argument.startswith(prefix):
            try:
                return int(argument[len(prefix) :])
            except ValueError as error:
                raise CrossValidationError(f"{name} requires a decimal integer value.") from error
    raise CrossValidationError(f"Required option is missing: {name}")


def _enrich_reference_inputs(
    command: str,
    arguments: Sequence[str],
    inputs: Mapping[str, Any],
) -> JsonObject:
    enriched = dict(inputs)
    if command == "public-key.rsa.educational.decrypt":
        enriched.update(
            {
                "p": _option_value(arguments, "--p"),
                "q": _option_value(arguments, "--q"),
                "e": _option_value(arguments, "--e"),
            }
        )
    elif command in {
        "public-key.ecc.negate",
        "public-key.ecc.add",
        "public-key.ecc.multiply",
        "public-key.ecc.subgroup",
    }:
        try:
            operation_index = arguments.index("ecc") + 2
            prime, coefficient_a, coefficient_b = arguments[operation_index : operation_index + 3]
        except (ValueError, IndexError) as error:
            raise CrossValidationError(
                "Unable to recover elliptic-curve parameters from the CryptoLab command."
            ) from error
        enriched.update(
            {
                "prime": int(prime),
                "a": int(coefficient_a),
                "b": int(coefficient_b),
            }
        )
    return enriched


def _run_json_process(
    command: Sequence[str],
    *,
    input_text: str | None = None,
    cwd: Path = ROOT,
) -> JsonObject:
    completed = subprocess.run(  # noqa: S603
        list(command),
        cwd=cwd,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        details = "\n".join(
            part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
        )
        raise CrossValidationError(
            f"Process failed with exit code {completed.returncode}:\n{details}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise CrossValidationError(
            f"Process did not return valid JSON:\n{completed.stdout}"
        ) from error
    if not isinstance(payload, dict):
        raise CrossValidationError("Process JSON output must be an object.")
    return payload


def _resolve_sage_executable(value: str | None) -> str:
    configured = value or os.environ.get("CRYPTOLAB_SAGE_EXECUTABLE") or "sage"
    path = shutil.which(configured)
    if path is None:
        candidate = Path(configured).expanduser()
        if candidate.is_file():
            path = str(candidate.resolve())
    if path is None:
        raise CrossValidationError(
            "SageMath is unavailable. Activate the SageMath environment or pass "
            "--sage-executable PATH."
        )
    return path


def _run_cryptolab(arguments: Sequence[str]) -> JsonObject:
    command = [sys.executable, "-m", "cryptolab", "--format", "json", *arguments]
    return _run_json_process(command)


def _run_sagemath(sage_executable: str, request: Mapping[str, Any]) -> JsonObject:
    command = [sage_executable, "-python", str(SAGE_REFERENCE)]
    return _run_json_process(command, input_text=json.dumps(request))


def _print_supported() -> None:
    print("Supported CryptoLab commands:")
    for command in sorted(CANONICALIZERS):
        print(f"  - {command}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sage-executable",
        help="SageMath executable path or command name; defaults to sage on PATH.",
    )
    parser.add_argument(
        "--list-supported",
        action="store_true",
        help="List supported CryptoLab command families and exit.",
    )
    parser.add_argument(
        "cryptolab_args",
        nargs=argparse.REMAINDER,
        help="CryptoLab command and arguments after --.",
    )
    return parser


def _raise_unsupported(display_name: str) -> NoReturn:
    supported = "\n".join(f"  - {item}" for item in sorted(CANONICALIZERS))
    raise CrossValidationError(
        f"Cross-validation is not supported for: {display_name}\nSupported commands:\n{supported}"
    )


def _require_object(value: Any, message: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CrossValidationError(message)
    return value


def main() -> int:
    """Run one direct CryptoLab/SageMath comparison."""

    arguments = _parser().parse_args()
    if arguments.list_supported:
        _print_supported()
        return 0

    cryptolab_args = list(arguments.cryptolab_args)
    if cryptolab_args and cryptolab_args[0] == "--":
        cryptolab_args.pop(0)
    if not cryptolab_args:
        print("Cross-validation failed: provide a CryptoLab command after --.")
        return 2

    try:
        cryptolab_payload = _run_cryptolab(cryptolab_args)
        command_name = str(cryptolab_payload.get("command", ""))
        canonicalizer = CANONICALIZERS.get(command_name)
        if canonicalizer is None:
            display_name = command_name or " ".join(cryptolab_args)
            _raise_unsupported(display_name)

        inputs = _require_object(
            cryptolab_payload.get("inputs"),
            "CryptoLab JSON has an invalid inputs field.",
        )
        result = _require_object(
            cryptolab_payload.get("result"),
            "CryptoLab JSON has an invalid result field.",
        )

        sage_executable = _resolve_sage_executable(arguments.sage_executable)
        reference_inputs = _enrich_reference_inputs(command_name, cryptolab_args, inputs)
        request = {
            "schema_version": "1.0",
            "command": command_name,
            "inputs": reference_inputs,
        }
        sage_payload = _run_sagemath(sage_executable, request)
        sage_result = _require_object(
            sage_payload.get("result"),
            "SageMath JSON has no result object.",
        )

        cryptolab_result = canonicalizer(inputs, result)
        matches = cryptolab_result == sage_result

        print(f"Operation: {command_name}")
        print(f"SageMath executable: {sage_executable}")
        if version := sage_payload.get("sagemath_version"):
            print(f"SageMath version: {version}")
        print("Inputs:")
        print(json.dumps(inputs, indent=2, sort_keys=True))
        print("CryptoLab result:")
        print(json.dumps(cryptolab_result, indent=2, sort_keys=True))
        print("SageMath result:")
        print(json.dumps(sage_result, indent=2, sort_keys=True))
        print(f"Results match: {matches}")

        if not matches:
            print("CryptoLab/SageMath cross-validation: FAILED")
            return 5
    except CrossValidationError as error:
        print(f"Cross-validation failed: {error}")
        return 4

    print(SUCCESS_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
