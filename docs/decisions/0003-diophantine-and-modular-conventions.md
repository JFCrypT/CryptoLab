# ADR 0003: Diophantine and modular conventions

- **Status:** accepted
- **Decision date:** 2026-08-01

## Decision

CryptoLab adopts the following conventions:

- linear Diophantine equations are limited to `ax + by = c` over the integers;
- solvability is determined by `gcd(a, b) | c` outside the fully degenerate case;
- the general solution uses one integer parameter `t`;
- equivalent equations are reduced by the common gcd of `a`, `b`, and `c` and then sign
  normalized;
- modular arithmetic requires `n >= 2`;
- residue representatives are canonical in `{0, ..., n - 1}`;
- fast exponentiation accepts non-negative exponents;
- linear congruences return every incongruent canonical solution;
- the Chinese Remainder Theorem implementation is generalized to compatible non-coprime
  moduli;
- non-zero zero-divisor lists exclude the zero class;
- residue and solution enumeration is bounded to prevent uncontrolled output.

## Consequences

A lack of solutions or inverses is represented as a successful mathematical result. Invalid
moduli and exceeded educational limits remain explicit errors. All CLI, JSON, LaTeX,
testing, and documentation layers use these conventions.
