# Changelog

All notable changes to CryptoLab will be documented in this file.

The project is being developed toward one initial public release, version 1.0.0. No public
pre-release is planned.

## Unreleased

### Added

- Repository baseline based on Python, uv, Typer, Rich, pytest, Hypothesis, Ruff, mypy,
  pre-commit, and MkDocs.
- Formal project metadata, contribution, security, citation, and documentation policies.
- Integer arithmetic educational module.
- CLI commands for Euclidean division, divisibility, divisors, primality testing,
  factorization, gcd, lcm, Euclidean traces, and extended gcd.
- Human, JSON, and LaTeX renderers for the implemented commands.
- Automated unit, property, CLI, and packaging tests for the implemented scope.
- Linear Diophantine equation solving, reduction, verification, and complete parameterized
  solution families.
- Canonical modular operations, fast modular exponentiation, inverses, units, and non-zero
  zero divisors.
- Linear congruence solving and the generalized Chinese Remainder Theorem.
- Algebraic descriptions of `Z_n`, additive and multiplicative element orders, generated
  subgroups, group generators, and primitive roots modulo a prime.
- Built-in Latin and Spanish uppercase alphabets plus strict custom JSON alphabet loading.
- Caesar encryption, decryption, modular transformation tables, exhaustive key enumeration,
  and basic character-frequency analysis.
- Vigenère encryption, decryption, and repeated-key alignment with explicit unknown-symbol
  behavior.
- Polybius grid construction, canonical coordinate tokens, preserved Unicode tokens,
  encryption, decryption, and coordinate validation.
- Documentation and automated tests for algebraic structures and classical ciphers.

### Fixed

- Corrected the initial Ruff and mypy configuration and implementation issues.
- Removed the deprecated license classifier while retaining PEP 639 license metadata.
- Clarified that pre-commit hook installation requires an initialized Git repository.
- Finalized type-only imports and dataclass narrowing for clean Ruff and mypy checks.
