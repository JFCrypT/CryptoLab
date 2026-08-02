from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COORDINATOR = ROOT / "scripts/cross_validate.py"


def _write_fake_sage(path: Path, *, mismatch: bool = False) -> None:
    inverse_expression = "78" if mismatch else "pow(value, -1, modulus)"
    path.write_text(
        f"""#!/usr/bin/env python3
import json
import math
import sys

request = json.load(sys.stdin)
command = request["command"]
inputs = request["inputs"]
if command != "modular.inverse":
    print(json.dumps({{"error": f"unsupported fake command: {{command}}"}}))
    raise SystemExit(1)
value = inputs["value"]
modulus = inputs["modulus"]
divisor = math.gcd(value, modulus)
result = {{
    "exists": divisor == 1,
    "gcd": divisor,
    "inverse": {inverse_expression} if divisor == 1 else None,
}}
print(json.dumps({{
    "schema_version": "1.0",
    "command": command,
    "sagemath_version": "test-double",
    "result": result,
}}))
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _run_cross_validation(fake_sage: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(COORDINATOR),
            "--sage-executable",
            str(fake_sage),
            "--",
            *arguments,
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_dynamic_modular_inverse_cross_validation(tmp_path: Path) -> None:
    fake_sage = tmp_path / "sage"
    _write_fake_sage(fake_sage)

    completed = _run_cross_validation(fake_sage, "modular", "inverse", "13", "200")

    assert completed.returncode == 0
    assert '"inverse": 77' in completed.stdout
    assert "Results match: True" in completed.stdout
    assert "CryptoLab/SageMath cross-validation: PASSED" in completed.stdout


def test_cross_validation_detects_mismatch(tmp_path: Path) -> None:
    fake_sage = tmp_path / "sage"
    _write_fake_sage(fake_sage, mismatch=True)

    completed = _run_cross_validation(fake_sage, "modular", "inverse", "13", "200")

    assert completed.returncode == 5
    assert "Results match: False" in completed.stdout
    assert "CryptoLab/SageMath cross-validation: FAILED" in completed.stdout


def test_cross_validation_rejects_unsupported_command(tmp_path: Path) -> None:
    fake_sage = tmp_path / "sage"
    _write_fake_sage(fake_sage)

    completed = _run_cross_validation(
        fake_sage,
        "hashing",
        "digest",
        "sha256",
        "--message-text",
        "abc",
    )

    assert completed.returncode == 4
    assert "Cross-validation is not supported for: hashing.digest" in completed.stdout


def test_sagemath_reference_is_dynamic_and_stdin_driven() -> None:
    source = (ROOT / "sagemath/compute_reference.py").read_text(encoding="utf-8")

    assert "json.load(sys.stdin)" in source
    assert "expected_factorization" not in source
    assert "sagemath/cross_validate.py" not in source
