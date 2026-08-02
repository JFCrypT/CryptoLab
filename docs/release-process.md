# Release process

CryptoLab uses a manual, auditable release process.

1. Confirm that the working tree is clean.
2. Synchronize the locked dependencies.
3. Run linting, formatting, typing, tests, pre-commit, and strict documentation checks.
4. Build the wheel and source distribution.
5. Run the repository-owned release checker against the built distributions.
6. Install the wheel in an isolated environment and execute representative CLI commands.
7. Confirm that every mandatory GitHub Actions job succeeds.
8. Create the release commit if needed.
9. Create the annotated version tag only after all mandatory evidence is complete.

The mandatory local sequence is:

```bash
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
uv run pre-commit run --all-files --show-diff-on-failure
uv run mkdocs build --strict
uv build --no-sources
uv run python scripts/check_release.py --dist-dir dist
```

## Optional SageMath comparison

SageMath is not part of release acceptance. When additional mathematical evidence is desired,
activate SageMath and compare one or more supported operations:

```bash
source /home/jfcrypt/miniforge3/bin/activate sage

uv run python scripts/cross_validate.py -- integer gcd 250 110
uv run python scripts/cross_validate.py -- modular inverse 13 200
uv run python scripts/cross_validate.py -- \
  public-key ecc multiply 17 2 2 3 5:1
```

The optional GitHub Actions workflow is manually dispatchable and does not participate in the
mandatory release-readiness dependency chain.

## Tagging

The annotated tag must identify the exact validated commit:

```bash
git tag -a v1.0.0 -m "CryptoLab 1.0.0"
```

A release must not claim certification, formal verification, independent auditing, universal
production readiness, or unconditional security.
