# Optional direct SageMath cross-validation

CryptoLab provides an optional mechanism that calculates one supported educational operation
with two independent execution paths and compares their normalized results.

SageMath is not required for:

- installing the wheel;
- using the `cryptolab` CLI;
- running the mandatory Python test suite;
- mandatory CI;
- release acceptance.

SageMath is required only when a contributor explicitly requests this additional comparison.

## Architecture

The implementation has two repository-owned programs with separate responsibilities:

```text
scripts/cross_validate.py
sagemath/compute_reference.py
```

The coordinator, `scripts/cross_validate.py`, runs with CryptoLab's Python environment. It:

1. receives a normal CryptoLab command after `--`;
2. executes the real CryptoLab CLI with forced JSON output;
3. extracts the normalized command name and inputs;
4. launches SageMath as an external process;
5. sends the same normalized inputs as JSON;
6. compares canonical CryptoLab and SageMath results;
7. reports a match or mismatch.

The reference process, `sagemath/compute_reference.py`, runs under SageMath. It:

- reads a request from standard input;
- maps the requested educational operation to SageMath facilities;
- calculates with the supplied runtime parameters;
- returns JSON on standard output;
- never imports CryptoLab;
- contains no fixed expected results.

The normal package under `src/cryptolab` never imports SageMath.

## Usage without SageMath

```bash
uv run cryptolab modular inverse 13 200
```

This executes only CryptoLab and produces the normal CLI result.

## Usage with SageMath comparison

Activate SageMath and provide the same command to the coordinator:

```bash
source /home/jfcrypt/miniforge3/bin/activate sage

uv run python scripts/cross_validate.py -- \
  modular inverse 13 200
```

Representative output:

```text
Operation: modular.inverse
CryptoLab result:
{
  "exists": true,
  "gcd": 1,
  "inverse": 77
}
SageMath result:
{
  "exists": true,
  "gcd": 1,
  "inverse": 77
}
Results match: True
CryptoLab/SageMath cross-validation: PASSED
```

The user enters the operation and parameters once. The coordinator performs both calculations.
The user does not write SageMath code.

## Supported operations

The dynamic mapping covers selected educational mathematics and public-key examples:

- integer factorization, gcd, lcm, and extended gcd;
- linear Diophantine solving;
- modular inverses and generalized CRT;
- element order and primitive roots;
- educational RSA inspection, encryption, and decryption;
- educational finite-field Diffie-Hellman group inspection and exchange;
- educational elliptic-curve inspection, negation, addition, scalar multiplication, and
  generated subgroups.

The authoritative current list is available through:

```bash
uv run python scripts/cross_validate.py --list-supported
```

Modern library-backed primitives such as AES, ChaCha20-Poly1305, X25519, and Ed25519 are not
SageMath targets. They are validated through published vectors, round trips, invalid-input
tests, and the established cryptographic library.

## Process boundary

CryptoLab and SageMath may use different Python interpreters:

```text
CryptoLab .venv Python  -> CryptoLab result
SageMath Python         -> SageMath result
                                 |
                                 v
                         coordinator comparison
```

Only JSON crosses this boundary. SageMath is not installed into CryptoLab's `.venv`, and
CryptoLab is not imported into SageMath's Python environment.

## Exit behavior

- `0`: results match;
- `2`: no CryptoLab command was supplied;
- `4`: SageMath is unavailable, the command is unsupported, or one process failed;
- `5`: both calculations completed but their normalized results differ.

## Limitations

The comparison is only as broad as the explicitly supported operation mappings. Matching
results provide useful independent evidence, but they do not establish formal correctness,
side-channel resistance, certification, independent auditing, or production readiness.
