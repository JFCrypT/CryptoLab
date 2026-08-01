# CryptoLab — Applied Cryptography Laboratory

CryptoLab is a public, didactic, reproducible, and technically rigorous laboratory that
connects cryptographic mathematics with transparent educational implementations and the
correct use of modern cryptographic libraries.

CryptoLab is designed to demonstrate knowledge of theoretical and applied cryptography
without becoming a complete cryptographic suite, a production cryptographic library, or a
general-purpose security product.

> **Development status**
>
> CryptoLab is being developed toward a single initial public release: **version 1.0.0**.
> No public pre-release is planned. The repository may contain incomplete work before the
> `v1.0.0` tag exists. The package metadata uses the target version number, but the release
> is not considered available until the acceptance criteria are met and the tag is created.

## Project actions

CryptoLab is summarized by six actions:

- **COMPUTE** mathematical operations used in cryptography.
- **IMPLEMENT** transparent educational algorithms and correct library-backed operations.
- **VISUALIZE** intermediate states, tables, transformations, and protocol flows.
- **VALIDATE** results using tests, identities, and published vectors.
- **COMPARE** algorithms according to purpose, properties, assumptions, and limitations.
- **EXPLAIN** what each construction provides, how it works, and how it can fail.

## What CryptoLab is

CryptoLab is:

- an educational applied-cryptography laboratory;
- a bridge between cryptographic mathematics and modern APIs;
- a command-line project with structured, scriptable output;
- a collection of reproducible examples and controlled local laboratories;
- a public demonstration of mathematical, cryptographic, software, testing, and
  documentation skills.

## What CryptoLab is not

CryptoLab is not:

- a replacement for OpenSSL, `cryptography`, or PyCryptodome;
- a production key-management system;
- a TLS, PKI, or certificate implementation;
- a network scanner, proxy, pentesting framework, or attack platform;
- a web application, desktop application, cloud service, database application, or IoT
  system;
- a formally verified or independently audited cryptographic library.

## Implementation categories

Every public capability belongs to one of four categories:

- `educational`: transparent code intended for study and inspection;
- `library-backed`: modern cryptographic operations delegated to established libraries;
- `controlled-laboratory`: deliberately vulnerable local demonstrations approved by the
  project scope;
- `comparison`: structured contrasts between algorithms and constructions.

Educational code may expose intermediate values and is not necessarily constant-time or
suitable for protecting real data. Modern primitives are not reimplemented merely to
increase repository size.

## Version 1.0.0 scope

The complete initial scope includes:

### Cryptographic mathematics

- integer and natural-number conventions;
- Euclidean division;
- divisibility and divisor enumeration;
- prime and composite classification;
- bounded educational primality testing and factorization;
- greatest common divisor and least common multiple;
- Euclidean and extended Euclidean algorithms;
- Bézout identities;
- linear Diophantine equations;
- modular arithmetic, inverses, zero divisors, exponentiation, linear congruences, and the
  generalized Chinese Remainder Theorem;
- semigroups, monoids, groups, cyclic groups, rings, integral domains, fields, orders,
  generators, and primitive roots where directly relevant to cryptography.

### Classical cryptography and sequences

- Caesar, Vigenère, and Polybius ciphers;
- configurable alphabets;
- XOR, Vernam, and One-Time Pad requirements;
- Fibonacci LFSRs with one explicit convention;
- period, cycle detection, balance, runs, and basic periodic autocorrelation.

### Modern symmetric cryptography

- AES-128 and AES-256;
- ECB, CBC, CFB-128, OFB, CTR, GCM, and XTS;
- ChaCha20-Poly1305;
- correct handling of keys, IVs, nonces, counters, tweaks, associated data, tags, and
  padding;
- explicit security and misuse warnings.

### Hashing, authentication, and derivation

- SHA-256 and SHA3-256;
- HMAC-SHA-256;
- HKDF-SHA-256;
- file hashing, digest comparison, published vectors, and avalanche visualization.

### Public-key cryptography

- educational textbook RSA;
- RSA-OAEP and RSA-PSS through an established library;
- educational finite-field Diffie-Hellman;
- educational elliptic-curve arithmetic over small prime fields;
- X25519 with HKDF-based derivation;
- Ed25519 signing and verification.

### Controlled cryptanalysis laboratories

Version 1.0.0 contains exactly these four laboratories:

1. Caesar brute force;
2. Vernam key reuse;
3. ECB pattern leakage;
4. unauthenticated Diffie-Hellman man-in-the-middle.

All laboratory code operates only on project-generated data, repository fixtures, or
intentionally vulnerable local examples.

### Validation and comparison

- unit, integration, round-trip, boundary, invalid-input, and selected property-based tests;
- mathematical identity verification;
- selected NIST and RFC test vectors;
- optional standalone SageMath cross-validation;
- comparisons between educational and library-backed code, AES modes, AEAD constructions,
  hash and authentication mechanisms, finite-field and elliptic-curve key agreement, and
  RSA and Ed25519 signatures.

## Mathematical conventions

CryptoLab uses the following fixed conventions:

- `N = {1, 2, 3, ...}` and `N0 = {0, 1, 2, ...}`;
- Euclidean division returns the unique `q` and `r` satisfying `a = bq + r` and
  `0 <= r < |b|`;
- `gcd(a, b)` is always non-negative and `gcd(0, 0) = 0`;
- modular representatives belong to `{0, ..., n - 1}` with `n >= 2`;
- zero is excluded from the project's list of non-zero zero divisors;
- integer-to-byte conversion is unsigned, big-endian, and minimal unless a length is
  explicitly requested;
- text is encoded as UTF-8 with strict error handling;
- hexadecimal input uses an even number of characters with no prefix or separators.

These conventions must not change silently.

## Current implementation

The implemented mathematical foundation currently includes:

- Euclidean division;
- divisibility and complete divisor enumeration;
- gcd, lcm, Euclidean traces, extended gcd, and Bézout coefficients;
- bounded deterministic educational primality testing and factorization;
- complete solution classification for linear Diophantine equations;
- equivalent-equation reduction and candidate-solution verification;
- canonical modular arithmetic;
- fast modular exponentiation with structured traces;
- units, multiplicative inverses, and non-zero zero divisors;
- linear congruences with every canonical solution;
- the generalized Chinese Remainder Theorem for compatible non-coprime moduli;
- human, JSON, and LaTeX output;
- unit, integration, CLI, and property-based tests for the implemented domain.

The first public release remains version 1.0.0 and will be created only after the complete
scope is implemented and validated.

## Requirements

- Linux;
- Python 3.12 or newer;
- `uv` for dependency management, execution, locking, and builds.

Python 3.12, 3.13, and 3.14 are the intended CI matrix for version 1.0.0.

## Installation for development

```bash
cd /home/jfcrypt/Documents/Proyectos/CryptoLab
uv sync
```

Install the pre-commit hooks after the directory is a Git repository. A cloned repository already satisfies this requirement. For a source archive, initialize Git first:

```bash
git init -b main
uv run pre-commit install
```

## Quick start

Display the root help:

```bash
uv run cryptolab --help
```

Perform Euclidean division:

```bash
uv run cryptolab --explain integer divide -17 5
```

Expected mathematical result:

```text
-17 = 5(-4) + 3
0 <= 3 < 5
```

Use a negative divisor while preserving the same remainder convention:

```bash
uv run cryptolab --format json integer divide -17 -5
```

Compute an extended gcd:

```bash
uv run cryptolab --explain integer extended-gcd 250 110
```

Factor a small educational integer:

```bash
uv run cryptolab integer factor -92400
```

Solve a linear Diophantine equation:

```bash
uv run cryptolab --explain diophantine solve 33 17 1
```

Solve a linear congruence:

```bash
uv run cryptolab --explain modular solve-linear 15 30 55
```

Solve a generalized CRT system:

```bash
uv run cryptolab --explain modular crt \
  --congruence 5:7 \
  --congruence 0:6 \
  --congruence=-1:5
```

## Output formats

The root CLI supports:

```text
--format human|json|latex
--explain
--output PATH
--no-color
--debug
--version
```

JSON output is designed for scripting and keeps human warnings out of standard output.
LaTeX output is available only for commands with a meaningful mathematical
representation.

## Testing and quality

Run the complete test suite:

```bash
uv run pytest
```

Run linting and formatting checks:

```bash
uv run ruff check .
uv run ruff format --check .
```

Run strict static typing:

```bash
uv run mypy
```

Run all pre-commit checks:

```bash
uv run pre-commit run --all-files
```

Build the wheel and source distribution:

```bash
uv build --no-sources
```

Build the documentation strictly:

```bash
uv run mkdocs build --strict
```

## Documentation

`README.md` is the complete self-contained entry point for the repository. The `docs/`
directory provides the detailed mathematical, cryptographic, laboratory, comparison, and
validation manual through MkDocs.

Publishing the generated static documentation through GitHub Pages is optional. CryptoLab
itself is not a web application and no cryptographic operation is executed remotely.

## Security statement

CryptoLab makes no claim of:

- certification;
- formal verification;
- independent security auditing;
- universal production readiness;
- complete side-channel resistance;
- unconditional security.

Do not use educational implementations to protect sensitive information. See
[`SECURITY.md`](SECURITY.md) for the reporting policy and project limitations.

## Repository policy

All repository content is written in English, including source code, identifiers, comments,
docstrings, tests, CLI output, documentation, workflows, commits, issues, and releases.
Configurable alphabet symbols are data and may contain non-English characters.

## Contributing

Contributions must preserve the approved scope, mathematical conventions, implementation
categories, English-only repository policy, test coverage, and limited cryptanalysis model.
See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Citation

Citation metadata is provided in [`CITATION.cff`](CITATION.cff).

## License

CryptoLab is released under the MIT License. See [`LICENSE`](LICENSE).
