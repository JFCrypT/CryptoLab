# ADR 0002: Mathematical conventions

- **Status:** accepted
- **Decision date:** 2026-08-01

## Decision

CryptoLab fixes the following conventions:

- `N` excludes zero and `N0` includes zero;
- Euclidean remainders satisfy `0 <= r < |b|`;
- gcd and lcm are non-negative;
- `gcd(0, 0) = 0`;
- a divisor is non-zero by project definition;
- non-zero zero divisors exclude the zero class;
- modular representatives are canonical and non-negative;
- integer-to-byte conversion is unsigned big-endian unless a documented construction
  requires another explicit encoding.

## Consequences

Implementations must not delegate negative-divisor Euclidean division blindly to Python.
Every renderer, test, and explanation uses the same conventions.
