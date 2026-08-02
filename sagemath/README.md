# Optional SageMath reference process

This directory contains the SageMath side of CryptoLab's optional direct cross-validation.
It is not part of the normal `cryptolab` runtime package and is not included in the wheel.

Users do not need to know or write SageMath code. The public coordinator is:

```bash
uv run python scripts/cross_validate.py -- <cryptolab command> <arguments>
```

For example:

```bash
uv run python scripts/cross_validate.py -- modular inverse 13 200
```

The coordinator performs the following steps:

1. executes the requested calculation through the real CryptoLab CLI in JSON mode;
2. sends the normalized command and inputs to `sagemath/compute_reference.py`;
3. runs that file with the `sage` executable as a separate process;
4. receives the SageMath result as JSON;
5. compares the CryptoLab and SageMath results;
6. exits with a non-zero status when they differ.

`compute_reference.py` reads all operation parameters dynamically from standard input. It
contains operation mappings, but it does not contain fixed expected results or release
fixtures.

## Local use

Activate an environment that makes `sage` available, then run the coordinator from the
repository root:

```bash
source /home/jfcrypt/miniforge3/bin/activate sage
sage --version

uv run python scripts/cross_validate.py -- \
  public-key ecc multiply 17 2 2 3 5:1
```

A successful comparison ends with:

```text
CryptoLab/SageMath cross-validation: PASSED
```

Use `--list-supported` to inspect the available educational operations:

```bash
uv run python scripts/cross_validate.py --list-supported
```

A non-default executable can be selected explicitly:

```bash
uv run python scripts/cross_validate.py \
  --sage-executable /path/to/sage \
  -- modular inverse 13 200
```

The optional GitHub Actions workflow uses the same coordinator through a pinned SageMath
container. It is manually dispatchable and does not block the mandatory CI or release gate.

Passing this comparison is additional validation evidence. It is not certification, formal
verification, an independent audit, or proof of production suitability.
