# Implementation categories

CryptoLab classifies every public capability as one of the following.

## Educational

Educational implementations prioritize readable mathematics, intermediate values,
structured traces, and small inspectable inputs. They may not be constant-time and must not
be used as production cryptographic code.

## Library-backed

Modern primitives are delegated to an established cryptographic library. CryptoLab remains
responsible for parameter validation, encoding, CLI behavior, documentation, warnings, and
tests, but does not reimplement the primitive.

## Controlled laboratory

A controlled laboratory reproduces one explicitly approved cryptographic failure using only
project-generated data, repository fixtures, or intentionally vulnerable local examples.
Version 1.1.0 retains exactly the four laboratories introduced in 1.0.0.

## Comparison

Comparison modules contrast algorithms according to purpose, assumptions, parameters,
authentication, padding, parallelization, random access, misuse risks, implementation status,
and limitations. No construction is declared universally superior without context.

## Post-quantum application of the categories

The 1.1.0 PQC extension preserves the same model:

- tiny negacyclic-ring and LWE-style calculations are `educational`;
- ML-KEM, ML-DSA, and SLH-DSA are `library-backed` through OpenSSL 3.5+ EVP;
- classical-versus-PQC tables are `comparison`;
- no new `controlled-laboratory` is added.

A standardized PQC implementation is not copied into CryptoLab merely to make its internals
visible. Exact FIPS algorithms remain the responsibility of the established backend.
