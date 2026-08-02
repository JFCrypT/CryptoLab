# ADR 0011: Release hardening and optional direct cross-validation

## Status

Accepted.

## Decision

CryptoLab 1.0.0 uses repository-owned release checks for metadata, documentation, scope,
package contents, and release acceptance. SageMath remains outside the normal runtime package
and is available as an optional direct cross-validation mechanism.

The cross-validation architecture is:

```text
scripts/cross_validate.py       coordinator and comparator
sagemath/compute_reference.py   SageMath-only reference calculator
```

The user supplies one normal CryptoLab operation and its parameters. The coordinator executes
CryptoLab, sends the same normalized inputs to SageMath, and compares the resulting values.
Neither program stores fixed expected outputs.

SageMath is not required for normal installation, CLI use, mandatory CI, or release acceptance.
A manually dispatchable GitHub Actions workflow provides public optional evidence through a
pinned SageMath container.

## Rationale

Python tests, mathematical identities, property-based tests, round trips, and published vectors
are the mandatory validation foundation. Direct SageMath comparison adds an independent
mathematical execution path without making a large computer-algebra system a runtime or release
dependency.

The dynamic design is stronger and clearer than comparing SageMath calculations only against
hardcoded constants. CryptoLab and SageMath both calculate from the same user-provided inputs,
and a separate coordinator compares their outputs.

## Rejected alternatives

- Mandatory SageMath for every contributor, CI run, and release was rejected because it adds a
  heavy Conda or container dependency without being necessary for normal package correctness.
- A SageMath script containing fixed release fixtures and expected results was rejected because
  it did not directly compare actual CryptoLab output.
- Installing SageMath inside the wheel environment was rejected because it would violate runtime
  isolation and substantially increase installation complexity.
- Executing SageMath automatically for every normal CLI operation was rejected because optional
  cross-validation must remain explicit and must not change the primary CLI behavior.

## Consequences

- `cryptolab ...` always executes only CryptoLab.
- `uv run python scripts/cross_validate.py -- ...` explicitly executes both engines.
- The wheel contains no SageMath material or dependency.
- The source distribution contains the coordinator, the reference calculator, and documentation.
- Mandatory CI and release readiness do not fail when SageMath is absent.
- The optional workflow can be run when independent mathematical comparison is desired.
- Passing cross-validation remains validation evidence, not certification or formal verification.
