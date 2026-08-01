# CryptoLab — Applied Cryptography Laboratory

CryptoLab connects cryptographic mathematics, transparent educational implementations,
modern library-backed cryptographic operations, lightweight visualization, reproducible
validation, algorithm comparison, and four controlled cryptanalysis laboratories.

The project is being developed toward a single initial public release, version 1.0.0. The
complete approved scope must be implemented, tested, documented, and reviewed before the
release tag is created.

## Documentation model

The repository README is the complete self-contained entry point. This manual provides the
more detailed mathematical, architectural, cryptographic, laboratory, comparison, and
validation material.

## Current internal implementation status

The implemented foundation currently provides:

- integer arithmetic, Euclidean traces, Bézout coefficients, primality, and factorization;
- complete linear Diophantine equation solving and verification;
- canonical modular operations and fast exponentiation;
- units, inverses, non-zero zero divisors, linear congruences, and generalized CRT;
- structural analysis of `Z_n`, additive and multiplicative element orders, generated
  subgroups, group generators, and primitive roots modulo a prime;
- configurable ordered alphabets;
- Caesar encryption, decryption, tables, complete key enumeration, and frequency counts;
- Vigenère encryption, decryption, and repeated-key alignment;
- Polybius grid construction, coordinate validation, encryption, and decryption;
- human, JSON, and LaTeX interfaces with automated validation.

These are internal development milestones only. They do not constitute a public pre-release.
