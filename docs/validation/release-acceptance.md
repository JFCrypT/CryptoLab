# Release acceptance

Version 1.0.0 is accepted only when every mandatory criterion succeeds on the exact commit
selected for release.

## Mandatory criteria

- the Git working tree is clean;
- Ruff linting and formatting checks pass;
- mypy strict checking passes;
- the complete pytest suite passes with branch coverage at or above 95 percent;
- pre-commit passes over all repository files;
- MkDocs builds in strict mode;
- the wheel and source distribution build successfully;
- the release checker validates metadata, documentation, scope, and archive contents;
- the wheel installs and executes outside the repository;
- no private-key or secret-file formats are present in the distributions;
- the GitHub Actions quality, tests, package, and release-readiness jobs pass;
- exactly the four approved controlled laboratories remain implemented.

The mandatory acceptance path does not require SageMath.

## Optional direct SageMath evidence

When SageMath is available, a contributor may compare a supported calculation through:

```bash
uv run python scripts/cross_validate.py -- \
  modular inverse 13 200
```

`scripts/cross_validate.py` executes the real CryptoLab CLI and sends the same normalized
inputs to `sagemath/compute_reference.py`. A mismatch returns a non-zero status. This is useful
additional evidence, but it is not a release gate.

The optional manually dispatchable GitHub Actions workflow can publish the same type of
comparison using a pinned SageMath container.

## Release commands

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
uv run pre-commit run --all-files --show-diff-on-failure
uv run mkdocs build --strict
uv build --no-sources
uv run python scripts/check_release.py --dist-dir dist
```

Passing these criteria does not constitute formal verification, certification, an independent
audit, guaranteed side-channel resistance, or unconditional production approval.
