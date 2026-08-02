# Getting started

CryptoLab requires Linux, Python 3.12 or newer, and `uv` for repository development.
SageMath is not required to install, test, build, release, or use the normal CLI.

## Development installation

```bash
cd /home/jfcrypt/Documents/Proyectos/CryptoLab
uv sync --locked
uv run pre-commit install
```

## Normal CLI use

```bash
uv run cryptolab --version
uv run cryptolab integer gcd 250 110
uv run cryptolab modular inverse 13 200
uv run cryptolab public-key ecc multiply 17 2 2 3 5:1
```

## Mandatory validation

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

## Optional SageMath cross-validation

Activate an environment that provides the `sage` executable:

```bash
source /home/jfcrypt/miniforge3/bin/activate sage
sage --version
```

Then provide a normal supported CryptoLab command after `--`:

```bash
uv run python scripts/cross_validate.py -- \
  modular inverse 13 200
```

The coordinator calculates with CryptoLab, calculates the same operation with SageMath through
`sagemath/compute_reference.py`, and compares the outputs. The operation parameters are entered
only once, and the user does not write SageMath code.

List the supported mappings with:

```bash
uv run python scripts/cross_validate.py --list-supported
```
