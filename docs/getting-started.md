# Getting started

CryptoLab requires Linux, Python 3.12 or newer, and `uv` for repository development.
SageMath is not required to install, test, build, release, or use the normal CLI. Standardized
post-quantum commands additionally require OpenSSL 3.5+ with ML-KEM, ML-DSA, and SLH-DSA
exposed through EVP; this does not change the requirements of the pre-existing commands.

## Development installation

```bash
cd /home/jfcrypt/Documents/Proyectos/CryptoLab
./scripts/install.sh
uv run pre-commit install
```

The installer synchronizes the locked Python environment. If the system OpenSSL does not
provide the standardized PQC algorithms, CryptoLab installs a pinned OpenSSL 3.5 LTS build
below `~/.local/share/cryptolab/openssl/` and discovers it automatically. The system
OpenSSL is not replaced. Use `./scripts/install.sh --without-pqc` when only the pre-existing
CryptoLab functionality is required.

## Normal CLI use

```bash
uv run cryptolab --version
uv run cryptolab integer gcd 250 110
uv run cryptolab modular inverse 13 200
uv run cryptolab public-key ecc multiply 17 2 2 3 5:1
```

## Post-quantum backend

```bash
openssl version
uv run cryptolab --explain post-quantum backend
uv run cryptolab post-quantum ml-kem parameters
uv run cryptolab post-quantum ml-dsa parameters
uv run cryptolab post-quantum slh-dsa parameters
```

The normal installer requires no environment variable. See
[Isolated OpenSSL PQC backend](post-quantum/backend.md) for installation, discovery, manual
overrides, and troubleshooting. `CRYPTOLAB_OPENSSL` remains an advanced explicit override.

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
